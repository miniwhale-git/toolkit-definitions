// manifest.json: build it, read it back strictly. The layout is the one in DefsFormat.kt.

import { HEADER_BYTES, cleanText, sha256Hex } from "./tkl.mjs";

export const FORMAT = 1;
export const MANIFEST = "manifest.json";
export const SIGNATURE = "manifest.json.sig";

/** The list files, in the order the manifest names them, with the table shape each must have. */
export const FILES = [
  { name: "apps-pkg.tkl", table: "pkg", keyBytes: 8, valueBytes: 2, required: true },
  { name: "apps-cert.tkl", table: "cert", keyBytes: 8, valueBytes: 2, required: true },
  { name: "apps-sha.tkl", table: "sha", keyBytes: 8, valueBytes: 2, required: false },
  { name: "hosts.tkl", table: "hosts", keyBytes: 6, valueBytes: 0, required: true },
];

/** Limits from DefsFormat, plus the budget for the host table. */
export const LIMITS = {
  manifestBytes: 64 * 1024,
  totalBytes: 12 * 1024 * 1024,
  hostsBytes: 4 * 1024 * 1024,
};

/** yyyymmddNN as a number. */
export function versionFor(date, seq) {
  if (!Number.isInteger(seq) || seq < 1 || seq > 99) throw new Error(`the sequence number must be 1 to 99, not ${seq}`);
  const day = date.toISOString().slice(0, 10).replace(/-/g, "");
  return Number(day) * 100 + seq;
}

/**
 * @param {{ version: number, built: Date, files: Array<{ name: string, bytes: Buffer, entries: number }>,
 *           sources: Array<{ name: string, licence: string, url: string, entries: number }> }} input
 * @returns {Buffer} the exact bytes to write and sign
 */
export function manifestBytes({ version, built, files, sources }) {
  const manifest = {
    format: FORMAT,
    version,
    built: built.toISOString().replace(/\.\d+Z$/, "Z"),
    files: files.map((f) => ({ name: f.name, sha256: sha256Hex(f.bytes), bytes: f.bytes.length, entries: f.entries })),
    sources: sources.map((s) => ({ name: s.name, licence: s.licence, url: s.url, entries: s.entries })),
  };
  return Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, "utf8");
}

const isCount = (n) => Number.isInteger(n) && n >= 0;

/** The keys each object may have; the app refuses any other key. */
const TOP_KEYS = ["format", "version", "built", "files", "sources"];
const FILE_KEYS = ["name", "sha256", "bytes", "entries"];
const SOURCE_KEYS = ["name", "licence", "url", "entries"];
/** Longest source name and licence the app shows whole (DefsManifest cuts longer ones). */
export const MAX_SOURCE_NAME = 100;
export const MAX_SOURCE_LICENCE = 40;
const MAX_SOURCES = 50;
const MAX_SOURCE_ENTRIES = 100_000_000;
/** yyyy-mm-ddThh:mm:ssZ, or with milliseconds as toISOString() writes them; the app reads both. */
const BUILT = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{3})?Z$/;
const URL_TEXT = /^https:\/\/[!-~]{1,192}$/;

/** True when yyyymmdd is a real calendar day in 2020 to 2099. */
function realDay(yyyymmdd) {
  const [y, m, d] = [Math.floor(yyyymmdd / 10000), Math.floor(yyyymmdd / 100) % 100, yyyymmdd % 100];
  if (y < 2020 || y > 2099) return false;
  const date = new Date(Date.UTC(y, m - 1, d));
  return date.getUTCFullYear() === y && date.getUTCMonth() === m - 1 && date.getUTCDate() === d;
}

/**
 * Parse and check a manifest by the rules the app's DefsManifest.parse applies, so a set that passes
 * here is not refused there. Throws a plain message naming the first thing wrong.
 */
export function parseManifest(bytes) {
  if (bytes.length > LIMITS.manifestBytes) throw new Error(`manifest.json is ${bytes.length} bytes, over the ${LIMITS.manifestBytes} limit`);
  let m;
  try {
    m = JSON.parse(bytes.toString("utf8"));
  } catch (error) {
    throw new Error(`manifest.json is not JSON (${error.message})`);
  }
  const bad = (why) => {
    throw new Error(`manifest.json: ${why}`);
  };
  const keys = (o, allowed, what) => {
    if (o === null || typeof o !== "object" || Array.isArray(o)) bad(`${what} is not an object`);
    const extra = Object.keys(o).find((k) => !allowed.includes(k));
    if (extra !== undefined) bad(`${what} has an unknown key "${extra}"`);
    const missing = allowed.find((k) => !(k in o));
    if (missing !== undefined) bad(`${what} has no "${missing}"`);
  };
  if (m === null || typeof m !== "object" || Array.isArray(m)) bad("not an object");
  if (m.format !== FORMAT) bad(`format is ${m.format}, expected ${FORMAT}`);
  keys(m, TOP_KEYS, "the manifest");
  if (!Number.isInteger(m.version) || m.version < 1_000_000_000 || m.version > 9_999_999_999) bad(`version ${m.version} is not yyyymmddNN`);
  if (!realDay(Math.floor(m.version / 100))) bad(`version ${m.version} is not a real date in 2020 to 2099`);
  if (typeof m.built !== "string" || !BUILT.test(m.built) || Number.isNaN(Date.parse(m.built))) bad(`built "${m.built}" is not a UTC time`);
  if (Date.parse(m.built) < Date.UTC(2020, 0, 1)) bad(`built "${m.built}" is before 2020`);
  if (!Array.isArray(m.files) || m.files.length === 0) bad("no files");
  if (m.files.length > FILES.length) bad(`${m.files.length} files, at most ${FILES.length}`);
  const names = new Set();
  let total = 0;
  for (const f of m.files) {
    keys(f, FILE_KEYS, "a file");
    if (typeof f.name !== "string" || !FILES.some((spec) => spec.name === f.name)) bad(`file name "${f.name}" is not a plain .tkl name the app knows`);
    if (names.has(f.name)) bad(`${f.name} is listed twice`);
    names.add(f.name);
    if (typeof f.sha256 !== "string" || !/^[0-9a-f]{64}$/.test(f.sha256)) bad(`${f.name}: sha256 is not 64 lower-case hex`);
    if (!isCount(f.bytes) || !isCount(f.entries)) bad(`${f.name}: bytes and entries must be whole numbers`);
    if (f.bytes <= HEADER_BYTES || f.bytes > LIMITS.totalBytes) bad(`${f.name}: size ${f.bytes} out of range`);
    if (f.entries < 1 || f.entries > Math.floor((f.bytes - HEADER_BYTES) / 6)) bad(`${f.name}: ${f.entries} entries cannot fit in ${f.bytes} bytes`);
    total += f.bytes;
  }
  for (const spec of FILES) if (spec.required && !names.has(spec.name)) bad(`${spec.name} is required and not listed`);
  if (total > LIMITS.totalBytes) bad(`files total ${total} bytes, more than ${LIMITS.totalBytes}`);
  if (!Array.isArray(m.sources) || m.sources.length === 0) bad("no sources: every list needs its credit");
  if (m.sources.length > MAX_SOURCES) bad(`${m.sources.length} sources, at most ${MAX_SOURCES}`);
  for (const s of m.sources) {
    keys(s, SOURCE_KEYS, "a source");
    if (![s.name, s.licence, s.url].every((v) => typeof v === "string" && v !== "") || !isCount(s.entries)) bad(`a source is missing name, licence, url or entries`);
    if (cleanText(s.name, MAX_SOURCE_NAME) !== s.name) bad(`source name "${s.name}" is not plain text of at most ${MAX_SOURCE_NAME} characters`);
    if (cleanText(s.licence, MAX_SOURCE_LICENCE) !== s.licence) bad(`licence of ${s.name} is not plain text of at most ${MAX_SOURCE_LICENCE} characters`);
    if (!URL_TEXT.test(s.url)) bad(`source url for ${s.name} is not a plain https address`);
    if (s.entries > MAX_SOURCE_ENTRIES) bad(`source ${s.name}: ${s.entries} entries`);
  }
  return m;
}
