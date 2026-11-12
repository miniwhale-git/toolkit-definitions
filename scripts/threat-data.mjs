#!/usr/bin/env node

/*
 * Toolkit's threat lists: build, check and query the signed set the app reads.
 * The file format is described in app/src/main/java/com/attnom/folio/security/defs/DefsFormat.kt.
 *
 *   node scripts/threat-data.mjs build --out DIR [--seq 01|auto] [--previous DIR] [--allow-drop] [--allow-growth]
 *                                      [--require-signature] [--date yyyymmdd] [--report FILE]
 *   node scripts/threat-data.mjs verify DIR
 *   node scripts/threat-data.mjs fetch-published --out DIR [--base URL]
 *        (exit 3: nothing is published yet; exit 4: what is published is signed by us but in an older format)
 *   node scripts/threat-data.mjs lookup DIR package|cert|sha|host VALUE      (exit 1 when not found)
 *   node scripts/threat-data.mjs sync-site [--check]    (copy this script into definitions-site/)
 *   node scripts/threat-data.mjs sign-fixture --out DIR (the fixed tiny set, signed with the key from the environment)
 *
 * build fetches the sources over https, writes the lists, manifest.json and, when a signing key is
 * given, manifest.json.sig. The key is an Ed25519 private key in PEM: a file named by
 * TOOLKIT_DEFS_KEY_FILE, or the text in TOOLKIT_DEFS_KEY. It is never printed.
 * Every gate prints what it counted. If one fails, nothing is written and the exit code is 1.
 * --report writes a short Markdown report (passed or not) for the run summary and the "Daily lists" issue.
 */

import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs as nodeParseArgs } from "node:util";
import { NO_KEEP_APPS, assemble, shortestHosts } from "./threat-sources/assemble.mjs";
import { collectAll, freshnessWarnings } from "./threat-sources/collect.mjs";
import { makeFetcher } from "./threat-sources/fetch.mjs";
import { fixtureSet } from "./threat-sources/fixture-set.mjs";
import { appKeepGate, checkSet, hostBudgetGate, hostGrowthGate, keepRescan, newCertificateLines, newCertificates, previousGates, readSet, shortNameGate, sourceGates } from "./threat-sources/gates.mjs";
import { buildKeeper, hostWalk, loadKeepList, normaliseHost } from "./threat-sources/hosts.mjs";
import { loadKeepApps } from "./threat-sources/keep-apps.mjs";
import { FILES, LIMITS, MANIFEST, SIGNATURE, manifestBytes, parseManifest, versionFor } from "./threat-sources/manifest.mjs";
import { buildReport } from "./threat-sources/report.mjs";
import { privateKeyFromEnv, publicKeys as productionKeys, signBytes, signedByAny } from "./threat-sources/sign.mjs";
import { MAX_DROP, MAX_GROWTH, MAX_REJECTED_SHARE, SOURCE_ROWS } from "./threat-sources/sources.mjs";
import { lookupText, openTable } from "./threat-sources/tkl.mjs";

const HERE = import.meta.dirname;

export class GateFailure extends Error {}

/** Print gate results; true when all passed. */
export function report(results, log = console.log) {
  for (const r of results) log(`${r.ok ? "PASS" : "FAIL"}  ${r.gate}: ${r.detail}`);
  return results.every((r) => r.ok);
}

/** A set read from a folder that must verify (used for --previous). */
export function loadVerifiedSet(dir, publicKey) {
  const set = readSet(dir);
  const failed = checkSet(set, { publicKey }).filter((r) => !r.ok);
  if (failed.length) throw new Error(`the previous set in ${dir} does not verify: ${failed.map((r) => `${r.gate}: ${r.detail}`).join("; ")}`);
  return { set, manifest: parseManifest(set.manifestBytes) };
}

/**
 * What the previous set says about each host source, for the growth hold: its host table, and each source's
 * entries in its manifest (by the row whose name it carries).
 */
export function previousHostData(previous, rows = SOURCE_ROWS) {
  if (!previous) return null;
  const bytes = previous.set.files.get("hosts.tkl");
  const entries = new Map();
  for (const s of previous.manifest.sources) {
    const row = rows.find((r) => r.name === s.name);
    if (row) entries.set(row.id, s.entries);
  }
  return { hosts: bytes ? openTable(bytes, "hosts.tkl") : null, entries };
}

/**
 * Build a set in memory and run every gate. Nothing touches the disk.
 * @returns {Promise<{ set: object, manifest: object, results: object[], ok: boolean, lines: string[], hosts: string[], report: { markdown: string, notify: string[] } }>}
 */
export async function buildSet({ fetchText, keep, keepApps = NO_KEEP_APPS, now = new Date(), seq = 1, previous = null, privateKey = null, publicKey, allowDrop = false, allowGrowth = false, requireSignature = false, rows = SOURCE_ROWS, maxRejected = MAX_REJECTED_SHARE, hostBudget, warnings = [], log = console.log }) {
  const parts = await collectAll(fetchText, { log });
  for (const part of parts) for (const note of part.notes) log(`${part.id}: ${note}`);
  const built = assemble(parts, { keep, keepApps, hostBudget, previous: previousHostData(previous, rows), allowGrowth });
  built.lines.forEach((l) => log(l));
  newCertificateLines(built.certs, previous?.set ?? null).forEach((l) => log(l));
  const shortest = shortestHosts(built.hosts);
  log(`the 50 listed hosts with the fewest labels: ${shortest.join(" ")}`);
  const sources = rows.map((row) => {
    const s = built.perSource.get(row.id);
    return { name: row.name, licence: row.licence, url: row.url, entries: s ? s.pkg + s.cert + s.sha + s.hosts : 0 };
  });
  const version = versionFor(now, seq);
  const bytes = manifestBytes({ version, built: now, files: built.files, sources });
  const signature = privateKey ? signBytes(bytes, privateKey) : null;
  const set = { manifestBytes: bytes, signature, files: new Map(built.files.map((f) => [f.name, f.bytes])) };
  const manifest = parseManifest(bytes);

  const results = [
    ...sourceGates(built.perSource, rows, maxRejected),
    ...previousGates(built.files, version, previous?.manifest ?? null, { maxDrop: MAX_DROP, allowDrop, maxGrowth: MAX_GROWTH, allowGrowth, now: now.getTime() }),
    appKeepGate(built.appDrops),
    shortNameGate(built.short),
    hostGrowthGate(built.held),
    hostBudgetGate(built.budget, built.hosts.length),
    keepRescan(built.hosts, buildKeeper(keep)),
    ...checkSet(set, { publicKey, keep, requireSignature }),
  ];
  const ok = results.every((r) => r.ok);
  const previousPkg = previous?.set.files.get("apps-pkg.tkl");
  const report = buildReport({
    version, ok, results, warnings, shortest,
    appDrops: built.appDrops,
    newCerts: newCertificates(built.certs, previous?.set ?? null),
    autoListed: built.autoListed,
    previousPkg: previousPkg ? openTable(previousPkg, "apps-pkg.tkl") : null,
    budget: built.budget,
    held: built.held,
    short: built.short,
  });
  return { set, manifest, results, ok, lines: built.lines, hosts: built.hosts, report };
}

/** The --date value as a time today or earlier (UTC), keeping the time of day of `now`. A later day is refused. */
export function buildDate(text, now = new Date()) {
  if (!/^\d{8}$/.test(text)) throw new Error("--date must be yyyymmdd");
  const date = new Date(`${text.slice(0, 4)}-${text.slice(4, 6)}-${text.slice(6)}T${now.toISOString().slice(11, 19)}Z`);
  if (Number.isNaN(date.getTime()) || date.toISOString().slice(0, 10).replace(/-/g, "") !== text) throw new Error(`--date ${text} is not a real day`);
  if (text > now.toISOString().slice(0, 10).replace(/-/g, "")) throw new Error(`--date ${text} is in the future; phones refuse a set dated ahead of their clock`);
  return date;
}

/** Write a checked set into a folder, then read it back and check it again. */
export function writeSet(dir, set, { publicKey, keep }) {
  mkdirSync(dir, { recursive: true });
  for (const name of readdirSync(dir)) if (name.endsWith(".tkl") && !set.files.has(name)) rmSync(path.join(dir, name));
  for (const [name, bytes] of set.files) writeFileSync(path.join(dir, name), bytes);
  writeFileSync(path.join(dir, MANIFEST), set.manifestBytes);
  if (set.signature !== null) writeFileSync(path.join(dir, SIGNATURE), set.signature);
  else rmSync(path.join(dir, SIGNATURE), { force: true });
  const failed = checkSet(readSet(dir), { publicKey, keep, requireSignature: set.signature !== null }).filter((r) => !r.ok);
  if (failed.length) throw new Error(`the set just written to ${dir} does not check out: ${failed.map((r) => `${r.gate}: ${r.detail}`).join("; ")}`);
}

/** Where the app downloads newer lists from; DefsFormat.BASE_URL says the same (a test compares). */
export const PUBLISHED_BASE = "https://miniwhale-git.github.io/toolkit-definitions/v1/";

/** What fetchPublished returns when the published set is ours (the signature verifies) but written in an older format. */
export class OlderFormat {
  constructor(reason) {
    this.reason = reason;
  }
}

/**
 * Download the published set into dir and check it as the app would (hashes, signature).
 * Returns null when nothing is published yet (the manifest answers 404), and an OlderFormat when the
 * manifest is signed by one of our keys but its host table has the 6-byte keys of the first format
 * (the app refuses such a set, so it cannot be the floor for the next one). Any other failure throws.
 * @param {{ base: string, dir: string, fetcher: ReturnType<typeof makeFetcher>, publicKey: import("node:crypto").KeyObject | import("node:crypto").KeyObject[] }} options
 */
export async function fetchPublished({ base, dir, fetcher, publicKey }) {
  const url = (name) => new URL(name, base).href;
  let manifestFile;
  try {
    manifestFile = await fetcher.bytes(url(MANIFEST), LIMITS.manifestBytes);
  } catch (error) {
    if (error.status === 404) return null;
    throw error;
  }
  const signature = await fetcher.bytes(url(SIGNATURE), 1024);
  let manifest;
  try {
    manifest = parseManifest(manifestFile);
  } catch (error) {
    const keys = Array.isArray(publicKey) ? publicKey : [publicKey];
    if (signedByAny(manifestFile, signature.toString("utf8"), keys) < 0) throw error;
    const hosts = await fetcher.bytes(url("hosts.tkl"), LIMITS.totalBytes);
    if (hosts.length >= 16 && hosts.toString("latin1", 0, 4) === "TKL1" && hosts[4] === 6) {
      return new OlderFormat(`hosts.tkl has 6-byte keys; this format needs 8 (${error.message})`);
    }
    throw error;
  }
  mkdirSync(dir, { recursive: true });
  writeFileSync(path.join(dir, MANIFEST), manifestFile);
  writeFileSync(path.join(dir, SIGNATURE), signature);
  for (const file of manifest.files) {
    if (!/^[a-z0-9-]+\.tkl$/.test(file.name)) throw new Error(`the published manifest names "${file.name}"`);
    writeFileSync(path.join(dir, file.name), await fetcher.bytes(url(file.name), LIMITS.totalBytes));
  }
  return loadVerifiedSet(dir, publicKey).manifest;
}

/** Look one thing up in a folder of lists, the way the app does. */
export function lookupIn(dir, kind, value) {
  const spec = { package: "pkg", cert: "cert", sha: "sha", host: "hosts" }[kind];
  if (!spec) throw new Error(`unknown kind "${kind}"; use package, cert, sha or host`);
  const file = FILES.find((f) => f.table === spec).name;
  if (!existsSync(path.join(dir, file))) return { tried: [], found: null, note: `${file} is not in ${dir}` };
  const table = openTable(readFileSync(path.join(dir, file)), file);
  if (kind === "host") {
    const host = normaliseHost(value);
    if (!host) return { tried: [], found: null, note: `"${value}" is not a usable host` };
    const tried = [];
    for (const name of hostWalk(host)) {
      tried.push(name);
      if (lookupText(table, name) !== null) return { tried, found: name, note: `${file}: ${name} is listed` };
    }
    return { tried, found: null, note: `${file}: none of ${tried.join(", ")} is listed` };
  }
  const text = kind === "package" ? value : value.toLowerCase();
  const label = lookupText(table, text);
  return { tried: [text], found: label, note: label === null ? `${file}: not listed` : `${file}: ${label}` };
}

// ---- the copy for the public repository ----------------------------------------------------------------

const SITE = path.join(HERE, "..", "definitions-site");
const SITE_FILES = ["threat-data.mjs", "threat-data.test.mjs", "threat-rules.test.mjs"];

/** The files the public repository holds a copy of: [from, to] pairs. */
export function siteCopies() {
  const pairs = SITE_FILES.map((f) => [path.join(HERE, f), path.join(SITE, "scripts", f)]);
  const walk = (dir, rel = "") =>
    readdirSync(path.join(dir, rel), { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(dir, path.join(rel, e.name)) : [rel ? path.join(rel, e.name) : e.name]));
  for (const rel of walk(path.join(HERE, "threat-sources"))) pairs.push([path.join(HERE, "threat-sources", rel), path.join(SITE, "scripts", "threat-sources", rel)]);
  return pairs;
}

function syncSite({ check }) {
  const stale = siteCopies().filter(([from, to]) => !existsSync(to) || !readFileSync(from).equals(readFileSync(to)));
  if (check) return stale.map(([, to]) => path.relative(SITE, to));
  for (const [from, to] of stale) {
    mkdirSync(path.dirname(to), { recursive: true });
    cpSync(from, to);
  }
  return stale.map(([, to]) => path.relative(SITE, to));
}

// ---- command line -------------------------------------------------------------------------------------------

export function parseCommandLine(argv) {
  const { values, positionals } = nodeParseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      out: { type: "string" },
      seq: { type: "string", default: "01" },
      previous: { type: "string" },
      date: { type: "string" },
      "allow-drop": { type: "boolean", default: false },
      "allow-growth": { type: "boolean", default: false },
      "require-signature": { type: "boolean", default: false },
      check: { type: "boolean", default: false },
      report: { type: "string" },
      base: { type: "string", default: PUBLISHED_BASE },
    },
  });
  return { command: positionals[0], args: positionals.slice(1), flags: values };
}

async function main(argv) {
  const { command, args, flags } = parseCommandLine(argv);
  const publicKey = productionKeys();
  const keep = loadKeepList();

  if (command === "build") {
    if (!flags.out) throw new Error("build needs --out DIR");
    const now = flags.date ? buildDate(flags.date) : new Date();
    const previous = flags.previous ? loadVerifiedSet(flags.previous, publicKey) : null;
    let seq = Number(flags.seq);
    if (flags.seq === "auto") {
      const sameDay = previous && Math.floor(previous.manifest.version / 100) === Math.floor(versionFor(now, 1) / 100);
      seq = sameDay ? (previous.manifest.version % 100) + 1 : 1;
    }
    const privateKey = privateKeyFromEnv();
    if (!privateKey) {
      const why = "no signing key: set TOOLKIT_DEFS_KEY_FILE or TOOLKIT_DEFS_KEY";
      if (flags["require-signature"]) throw new Error(why);
      console.log(`WARNING  ${why}; the set will be UNSIGNED and the app will refuse it`);
    }
    const fetchText = makeFetcher({ log: (s) => console.log(s) });
    const warnings = await freshnessWarnings(fetchText, now);
    for (const warning of warnings) {
      console.log(`WARNING  ${warning}`);
      if (process.env.GITHUB_ACTIONS) console.log(`::warning::${warning}`);
    }
    const built = await buildSet({
      fetchText, keep, keepApps: loadKeepApps(), now, seq, previous, privateKey, publicKey, warnings,
      allowDrop: flags["allow-drop"], allowGrowth: flags["allow-growth"], requireSignature: Boolean(privateKey) || flags["require-signature"],
    });
    if (flags.report) {
      writeFileSync(flags.report, built.report.markdown);
      console.log(`report written to ${flags.report}${built.report.notify.length ? `; needs a look: ${built.report.notify.join("; ")}` : ""}`);
    }
    if (!report(built.results)) throw new GateFailure("a gate failed; nothing was written");
    writeSet(flags.out, built.set, { publicKey, keep });
    console.log(`wrote ${built.set.files.size} lists, ${MANIFEST}${built.set.signature ? ` and ${SIGNATURE}` : ""} to ${flags.out}`);
    return 0;
  }

  if (command === "sign-fixture") {
    if (!flags.out) throw new Error("sign-fixture needs --out DIR");
    const privateKey = privateKeyFromEnv();
    if (!privateKey) throw new Error("no signing key: set TOOLKIT_DEFS_KEY_FILE or TOOLKIT_DEFS_KEY");
    const fixture = fixtureSet();
    const set = { ...fixture, signature: signBytes(fixture.manifestBytes, privateKey) };
    const index = signedByAny(set.manifestBytes, set.signature, publicKey);
    if (index < 0) throw new Error("the key in the environment is not one of the production keys (DefsFormat.PUBLIC_KEYS); nothing was written");
    writeSet(flags.out, set, { publicKey, keep });
    console.log(`wrote the fixture set to ${flags.out}, signed by public key ${index + 1} of ${publicKey.length}`);
    return 0;
  }

  if (command === "verify") {
    if (!args[0]) throw new Error("verify needs a folder");
    const set = readSet(args[0]);
    const results = checkSet(set, { publicKey, keep, requireSignature: true });
    const passed = report(results);
    console.log(passed ? `verify: ${args[0]} is a valid set` : `verify: ${args[0]} FAILED`);
    return passed ? 0 : 1;
  }

  if (command === "fetch-published") {
    if (!flags.out) throw new Error("fetch-published needs --out DIR");
    const fetcher = makeFetcher({ hosts: new Set([new URL(flags.base).hostname]), log: (line) => console.log(line) });
    const manifest = await fetchPublished({ base: flags.base, dir: flags.out, fetcher, publicKey });
    if (manifest === null) {
      console.log(`nothing is published at ${flags.base} yet`);
      return 3;
    }
    if (manifest instanceof OlderFormat) {
      console.log(`the published set is signed by us but in an older format the app refuses: ${manifest.reason}`);
      return 4;
    }
    console.log(`downloaded the published set, version ${manifest.version}, and it verifies`);
    return 0;
  }

  if (command === "lookup") {
    if (args.length !== 3) throw new Error("lookup needs a folder, a kind (package, cert, sha, host) and a value");
    const answer = lookupIn(args[0], args[1], args[2]);
    console.log(answer.note);
    return answer.found === null ? 1 : 0;
  }

  if (command === "sync-site") {
    const changed = syncSite({ check: flags.check });
    if (flags.check) {
      console.log(changed.length ? `definitions-site is out of date: ${changed.join(", ")}` : "definitions-site copy is current");
      return changed.length ? 1 : 0;
    }
    console.log(changed.length ? `updated ${changed.length} files in definitions-site/scripts` : "definitions-site copy was already current");
    return 0;
  }

  throw new Error("usage: threat-data.mjs build --out DIR | verify DIR | fetch-published --out DIR | lookup DIR package|cert|sha|host VALUE | sync-site [--check] | sign-fixture --out DIR");
}

// Run only when started as a script, so the test file can import the functions.
const startedAsScript = process.argv[1] && realpathSync(fileURLToPath(import.meta.url)) === realpathSync(path.resolve(process.argv[1]));
if (startedAsScript) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (error) => {
      process.stderr.write(`${error.message}\n`);
      process.exit(1);
    },
  );
}
