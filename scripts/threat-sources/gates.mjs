// The checks a set of lists must pass before it is written or published. Each gate returns
// { gate, ok, detail }; the detail always says what was counted, so a pass is not a silent one.

import { readFileSync, readdirSync, existsSync } from "node:fs";
import path from "node:path";
import { canaryEntry } from "./canary.mjs";
import { hostWalk } from "./hosts.mjs";
import { MAX_NEW_HITS } from "./keep-apps.mjs";
import { labelAllowed } from "./labels.mjs";
import { FILES, LIMITS, MANIFEST, SIGNATURE, datedAhead, parseManifest } from "./manifest.mjs";
import { signedByAny } from "./sign.mjs";
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
 * @param {{ publicKey: import("node:crypto").KeyObject | import("node:crypto").KeyObject[], keep?: Map<string, boolean>, requireSignature?: boolean }} options
 *   publicKey may be one key or the list of keys any of which may sign (DefsFormat.PUBLIC_KEYS).
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
    const keys = Array.isArray(publicKey) ? publicKey : [publicKey];
    const index = signedByAny(set.manifestBytes, set.signature, keys);
    out.push(result("signature", index >= 0, index >= 0 ? `valid for public key ${index + 1} of ${keys.length}` : `does not verify against any of the ${keys.length} public keys`));
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

  // Labels: each one the app shows as it is (LabelText.shown), so nothing from a source reaches the screen unfiltered.
  const labels = [...tables.values()].flatMap((t) => t.labels);
  const badLabels = labels.filter((l) => !labelAllowed(l));
  out.push(result("labels", badLabels.length === 0, badLabels.length ? `not plain names: ${badLabels.slice(0, 5).map((l) => JSON.stringify(l)).join(", ")}` : `${labels.length} labels pass the label filter`));

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

/**
 * The set must be newer than the previous one; no file (nor the total) may shrink by more than maxDrop;
 * the app entries together may not grow by more than maxGrowth (sudden growth is as suspicious as a drop).
 * A previous set dated more than two days after `now` is one phones refuse, so it does not set the floor.
 */
export function previousGates(files, version, previousManifest, { maxDrop, allowDrop, maxGrowth = Infinity, allowGrowth = false, now = Date.now() }) {
  if (!previousManifest) return [result("previous", true, "no previous set given, nothing to compare")];
  const ahead = datedAhead(previousManifest, now);
  const out = [
    ahead
      ? result("version", true, `previous ${previousManifest.version} (built ${previousManifest.built}) is dated ahead of this build; phones refuse it, so ${version} may follow it`)
      : result("version", version > previousManifest.version, `${version} against previous ${previousManifest.version}; it must be higher`),
  ];
  const sum = (list) => list.reduce((n, f) => n + f.entries, 0);
  const apps = (list) => sum(list.filter((f) => f.name !== "hosts.tkl"));
  const before = apps(previousManifest.files);
  const after = apps(files);
  const grew = before > 0 && after > before * (1 + maxGrowth);
  const growth = before > 0 ? `${(((after - before) / before) * 100).toFixed(1)}%` : "n/a";
  out.push(result("growth", !grew || allowGrowth, `app entries ${before} -> ${after} (${growth})${grew ? (allowGrowth ? " (allowed by --allow-growth)" : `; more than ${maxGrowth * 100}% up`) : `, at most ${maxGrowth * 100}% up`}`));
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

/**
 * The app keep-lists dropped what they must; more than `maxNew` distinct new hits in one run (entries the
 * keep files do not mark "known") look like a tampered source, so the build stops. Every hit is named.
 */
export function appKeepGate(appDrops, maxNew = MAX_NEW_HITS) {
  const byItem = new Map();
  for (const d of appDrops) {
    const key = `${d.table} ${d.text}`;
    const seen = byItem.get(key) ?? { ...d, sources: new Set(), labels: new Set() };
    seen.sources.add(d.source);
    seen.labels.add(d.label);
    byItem.set(key, seen);
  }
  const items = [...byItem.values()];
  const fresh = items.filter((d) => !d.known);
  const named = items.map((d) => `${d.table === "pkg" ? "package" : "certificate"} ${d.text} (${[...d.labels].slice(0, 3).join(", ")}; from ${[...d.sources].join(", ")}; ${d.rule}${d.known ? ", known" : ", NEW"})`);
  const ok = fresh.length <= maxNew;
  return result(
    "app keep-lists",
    ok,
    `${items.length} distinct entries dropped, ${fresh.length} new (at most ${maxNew})${ok ? "" : ": a source may have been tampered with; review each and mark it \"known\" or fix the source"}${named.length ? `: ${named.join("; ")}` : ""}`,
  );
}

/** Nothing is cut to fit: a host table over its budget stops the build, with the counts. */
export function hostBudgetGate(budget) {
  const over = [...budget.over].map(([id, n]) => `${id} ${n}`).join(", ");
  return result("host budget", budget.wanted <= budget.cap, budget.wanted <= budget.cap ? `${budget.wanted} hosts of ${budget.cap}` : `${budget.wanted} hosts for ${budget.cap} places; over by ${budget.wanted - budget.cap} (${over}). Raise the budget in manifest.mjs and DefsFormat, or drop a source`);
}

/**
 * Certificate entries that the previous set did not have, each as a line for the build log: a new
 * certificate decides about every app signed with it, so a person should be able to see each one.
 * @param {Array<{ text: string, label: string }>} entries the certificate items that went into the new table
 * @param {{ files: Map<string, Buffer> } | null} previousSet
 */
export function newCertificateLines(entries, previousSet) {
  if (!previousSet) return [`certificates: no previous set, ${new Set(entries.map((e) => e.text)).size} entries not compared`];
  const bytes = previousSet.files.get("apps-cert.tkl");
  if (!bytes) return ["certificates: the previous set has no apps-cert.tkl"];
  const table = openTable(bytes, "apps-cert.tkl");
  const fresh = new Map();
  for (const e of entries) if (!fresh.has(e.text) && lookupText(table, e.text) === null) fresh.set(e.text, e.label);
  return [`certificates: ${fresh.size} new against the previous set`, ...[...fresh].map(([hex, label]) => `new certificate entry: ${hex} ${label}`)];
}
