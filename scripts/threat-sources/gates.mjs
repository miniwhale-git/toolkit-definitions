// The checks a set of lists must pass before it is written or published. Each gate returns
// { gate, ok, detail }; the detail always says what was counted, so a pass is not a silent one.

import { readFileSync, readdirSync, existsSync } from "node:fs";
import path from "node:path";
import { canaryEntry } from "./canary.mjs";
import { hostWalk } from "./hosts.mjs";
import { FILES, LIMITS, MANIFEST, SIGNATURE, parseManifest } from "./manifest.mjs";
import { signatureValid } from "./sign.mjs";
import { lookupText, openTable, sha256Hex, tableProblems } from "./tkl.mjs";

const result = (gate, ok, detail) => ({ gate, ok, detail });

/** Read a set from a folder: manifest, signature (or null) and every .tkl file in it. */
export function readSet(dir) {
  if (!existsSync(path.join(dir, MANIFEST))) throw new Error(`${dir} has no ${MANIFEST}`);
  const files = new Map();
  for (const name of readdirSync(dir)) if (name.endsWith(".tkl")) files.set(name, readFileSync(path.join(dir, name)));
  const sigPath = path.join(dir, SIGNATURE);
  return { manifestBytes: readFileSync(path.join(dir, MANIFEST)), signature: existsSync(sigPath) ? readFileSync(sigPath, "utf8") : null, files };
}

/** True when the table lists the host or one of its parent names (the walk the app makes). */
export const hostListed = (table, host) => hostWalk(host).some((name) => lookupText(table, name) !== null);

/**
 * Everything that can be checked from the set alone: it is what `build` runs before writing and
 * what `verify` runs on a folder.
 * @param {{ manifestBytes: Buffer, signature: string | null, files: Map<string, Buffer> }} set
 * @param {{ publicKey: import("node:crypto").KeyObject, keep?: Map<string, boolean>, requireSignature?: boolean }} options
 */
export function checkSet(set, { publicKey, keep, requireSignature = true }) {
  const out = [];
  let manifest;
  try {
    manifest = parseManifest(set.manifestBytes);
    out.push(result("manifest", true, `format ${manifest.format}, version ${manifest.version}, built ${manifest.built}, ${manifest.files.length} files, ${manifest.sources.length} sources`));
  } catch (error) {
    return [result("manifest", false, error.message)];
  }

  if (set.signature === null) out.push(result("signature", !requireSignature, requireSignature ? "manifest.json.sig is missing" : "not signed (no signing key was given)"));
  else {
    const valid = signatureValid(set.manifestBytes, set.signature, publicKey);
    out.push(result("signature", valid, valid ? "valid for DefsFormat.PUBLIC_KEY" : "does not verify against the public key"));
  }

  // Files: present, hash, size and count as the manifest says, no extras.
  const fileProblems = [];
  const tables = new Map();
  for (const entry of manifest.files) {
    const spec = FILES.find((f) => f.name === entry.name);
    const bytes = set.files.get(entry.name);
    if (!spec) fileProblems.push(`${entry.name} is not a file the app knows`);
    else if (!bytes) fileProblems.push(`${entry.name} is listed but missing`);
    else if (bytes.length !== entry.bytes) fileProblems.push(`${entry.name}: ${bytes.length} bytes, manifest says ${entry.bytes}`);
    else if (sha256Hex(bytes) !== entry.sha256) fileProblems.push(`${entry.name}: SHA-256 differs from the manifest`);
    else {
      try {
        const table = openTable(bytes, entry.name);
        if (table.keyBytes !== spec.keyBytes || table.valueBytes !== spec.valueBytes) fileProblems.push(`${entry.name}: key/value bytes ${table.keyBytes}/${table.valueBytes}, expected ${spec.keyBytes}/${spec.valueBytes}`);
        else if (table.entryCount !== entry.entries) fileProblems.push(`${entry.name}: ${table.entryCount} entries, manifest says ${entry.entries}`);
        else tables.set(spec.table, table);
      } catch (error) {
        fileProblems.push(error.message);
      }
    }
  }
  for (const name of set.files.keys()) if (!manifest.files.some((f) => f.name === name)) fileProblems.push(`${name} is in the folder but not in the manifest`);
  for (const spec of FILES) if (spec.required && !manifest.files.some((f) => f.name === spec.name)) fileProblems.push(`${spec.name} is required and not listed`);
  out.push(result("files", fileProblems.length === 0, fileProblems.length ? fileProblems.join("; ") : manifest.files.map((f) => `${f.name} ${f.entries} entries, ${f.bytes} bytes, hash matches`).join("; ")));

  // Order and duplicates, label indexes.
  const tableIssues = [...tables.values()].flatMap(tableProblems);
  out.push(result("tables", tableIssues.length === 0, tableIssues.length ? tableIssues.join("; ") : `${tables.size} tables sorted by unsigned key bytes, no duplicate keys, label indexes in range`));

  // Canaries: every table answers its known entry, or the app refuses the set.
  const canaryIssues = [];
  for (const spec of FILES) {
    const table = tables.get(spec.table);
    if (!table) continue;
    const want = canaryEntry(spec.table);
    let got;
    try {
      got = spec.table === "hosts" ? hostListed(table, want.text) : lookupText(table, want.text);
    } catch (error) {
      got = error.message;
    }
    if (spec.table === "hosts" ? got !== true : got !== want.label) canaryIssues.push(`${spec.name} does not answer its canary ${want.text}${typeof got === "string" ? ` (${got})` : ""}`);
  }
  out.push(result("canaries", canaryIssues.length === 0 && tables.size > 0, canaryIssues.length ? canaryIssues.join("; ") : `${tables.size} tables answer their canary`));

  // Sizes.
  const total = [...set.files.values()].reduce((n, b) => n + b.length, 0);
  const hostsBytes = set.files.get("hosts.tkl")?.length ?? 0;
  const sizeIssues = [];
  if (set.manifestBytes.length > LIMITS.manifestBytes) sizeIssues.push(`manifest ${set.manifestBytes.length} > ${LIMITS.manifestBytes}`);
  if (total > LIMITS.totalBytes) sizeIssues.push(`lists ${total} > ${LIMITS.totalBytes}`);
  if (hostsBytes > LIMITS.hostsBytes) sizeIssues.push(`hosts.tkl ${hostsBytes} > ${LIMITS.hostsBytes}`);
  out.push(result("sizes", sizeIssues.length === 0, sizeIssues.length ? sizeIssues.join("; ") : `manifest ${set.manifestBytes.length} B, lists ${total} B of ${LIMITS.totalBytes}, hosts.tkl ${hostsBytes} B of ${LIMITS.hostsBytes}`));

  // The keep-list: no kept host (or a parent of one) may be found by the app's own lookup.
  if (keep) {
    const hosts = tables.get("hosts");
    if (!hosts) out.push(result("keep-list", false, "there is no host table to check"));
    else {
      const hits = [...keep.keys()].filter((host) => hostListed(hosts, host));
      out.push(result("keep-list", hits.length === 0, hits.length ? `listed although kept: ${hits.slice(0, 10).join(", ")}` : `${keep.size} kept hosts, none found by the lookup`));
    }
  }
  return out;
}

/** The least each source must give, and the share of unusable entries it may have. */
export function sourceGates(perSource, rows, maxRejected) {
  const out = [];
  for (const row of rows) {
    const s = perSource.get(row.id);
    const entries = s ? s.pkg + s.cert + s.sha + s.hosts : 0;
    out.push(result(`source ${row.id}`, entries >= row.min, `${entries} entries, at least ${row.min} needed`));
    const share = s && s.raw > 0 ? s.rejected / s.raw : 0;
    out.push(result(`unusable ${row.id}`, share <= maxRejected, `${s?.rejected ?? 0} of ${s?.raw ?? 0} entries unusable (${(share * 100).toFixed(2)}%), at most ${maxRejected * 100}%`));
  }
  return out;
}

/** The set must be newer than the previous one, and no file (nor the total) may shrink by more than maxDrop. */
export function previousGates(files, version, previousManifest, { maxDrop, allowDrop }) {
  if (!previousManifest) return [result("previous", true, "no previous set given, nothing to compare")];
  const out = [result("version", version > previousManifest.version, `${version} against previous ${previousManifest.version}; it must be higher`)];
  const sum = (list) => list.reduce((n, f) => n + f.entries, 0);
  const drops = [];
  const check = (label, now, before) => {
    if (before > 0 && now < before * (1 - maxDrop)) drops.push(`${label} ${before} -> ${now} (${(((before - now) / before) * 100).toFixed(1)}% less)`);
  };
  check("total", sum(files), sum(previousManifest.files));
  for (const f of files) check(f.name, f.entries, previousManifest.files.find((p) => p.name === f.name)?.entries ?? 0);
  for (const p of previousManifest.files) if (p.entries > 0 && !files.some((f) => f.name === p.name)) drops.push(`${p.name} ${p.entries} -> gone`);
  const ok = drops.length === 0 || allowDrop;
  out.push(result("drop", ok, drops.length ? `${drops.join("; ")}${allowDrop ? " (allowed by --allow-drop)" : `; more than ${maxDrop * 100}% down`}` : `total ${sum(previousManifest.files)} -> ${sum(files)}, no file down by more than ${maxDrop * 100}%`));
  return out;
}

/** Each host kept in the final list must pass the keep-list rules again, as a second look at the filter. */
export function keepRescan(hosts, keeper) {
  const bad = hosts.filter((host) => keeper.reason(host) !== null);
  return result("keep-list rescan", bad.length === 0, bad.length ? `still present: ${bad.slice(0, 10).join(", ")}` : `${hosts.length} hosts re-checked against the keep-list rules`);
}
