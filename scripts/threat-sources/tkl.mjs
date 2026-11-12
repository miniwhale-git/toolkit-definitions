// The .tkl table: writer, reader and binary search. The layout is the one in
// app/src/main/java/com/attnom/folio/security/defs/DefsFormat.kt; change both together.
//
//   0  "TKL1"   4  keyBytes u8 (always 8)   5  valueBytes u8 (0 or 2)   6  reserved u16 = 0
//   8  entryCount u32 BE   12  labelCount u32 BE   16  entries (key + value), ascending by key, no duplicates
//   ..  labels: labelCount x (u8 length, UTF-8 bytes)
//
// A key is the first 8 bytes of SHA-256 over the UTF-8 text of the item. Shorter keys are refused:
// at 6 bytes anyone could make a host name whose key equals a victim site's in about 2^48 hashes.

import { createHash } from "node:crypto";

export const MAGIC = "TKL1";
export const HEADER_BYTES = 16;
export const KEY_BYTES = 8;
export const MAX_LABEL = 60;

export const sha256 = (data) => createHash("sha256").update(data).digest();
export const sha256Hex = (data) => sha256(data).toString("hex");

/** First keyBytes (8) bytes of SHA-256 over the UTF-8 bytes of text. */
export function keyOf(text, keyBytes = KEY_BYTES) {
  return sha256(Buffer.from(text, "utf8")).subarray(0, keyBytes);
}

/**
 * Make text safe to show as one plain line, by the same rules as the app's LabelText.clean, so the
 * app shows exactly what was written: tabs, line breaks and every kind of space become one space;
 * other control, format (bidi marks, zero-width), private-use, unassigned and lone surrogate
 * characters are dropped; the result is cut to `max` UTF-16 units without splitting a pair.
 * Labels come from outside, so this runs on every one.
 */
export function cleanText(text, max) {
  const plain = String(text)
    .replace(/[\t\n\r\v\f\u0085\p{Zs}\p{Zl}\p{Zp}]+/gu, " ")
    .replace(/[\p{Cc}\p{Cf}\p{Co}\p{Cn}\p{Cs}]/gu, "")
    .replace(/ {2,}/g, " ")
    .trim();
  if (plain.length <= max) return plain;
  let cut = max;
  if (/[\ud800-\udbff]/.test(plain[cut - 1])) cut--;
  return plain.slice(0, cut).trimEnd();
}

/** A label as the app shows it: cleanText at MAX_LABEL. */
export const cleanLabel = (text) => cleanText(text, MAX_LABEL);

/**
 * Build a table.
 * @param {{ keyBytes?: 8, labelled: boolean, entries: Array<{ text: string, label?: string }> }} spec
 *   A labelled table needs a label on every entry; the other kind takes none. Entries whose key repeats are reduced to the first one given;
 *   the count of those is returned as `collisions` (the same text twice is not counted).
 * @returns {{ bytes: Buffer, entries: number, labels: string[], collisions: number }}
 */
export function writeTable({ keyBytes = KEY_BYTES, labelled, entries }) {
  if (keyBytes !== KEY_BYTES) throw new Error(`keyBytes must be ${KEY_BYTES}, not ${keyBytes}`);
  const withLabels = labelled;
  const valueBytes = withLabels ? 2 : 0;
  const byKey = new Map();
  let collisions = 0;
  for (const entry of entries) {
    if ((entry.label !== undefined) !== withLabels) throw new Error("a table holds labels on every entry or on none");
    const key = keyOf(entry.text, keyBytes);
    const hex = key.toString("hex");
    const seen = byKey.get(hex);
    if (seen) {
      if (seen.text !== entry.text) collisions++;
      continue;
    }
    byKey.set(hex, { key, text: entry.text, label: entry.label });
  }
  const sorted = [...byKey.values()].sort((a, b) => Buffer.compare(a.key, b.key));
  const labels = withLabels ? [...new Set(sorted.map((e) => e.label))].sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b))) : [];
  const labelIndex = new Map(labels.map((label, i) => [label, i]));
  const labelBytes = labels.map((label) => {
    const bytes = Buffer.from(label, "utf8");
    if (bytes.length === 0 || bytes.length > 255) throw new Error(`label "${label}" must be 1 to 255 bytes of UTF-8`);
    return bytes;
  });
  if (labels.length > 0xffff) throw new Error(`too many labels: ${labels.length}`);

  const entrySize = keyBytes + valueBytes;
  const total = HEADER_BYTES + sorted.length * entrySize + labelBytes.reduce((n, b) => n + 1 + b.length, 0);
  const out = Buffer.alloc(total);
  out.write(MAGIC, 0, "latin1");
  out[4] = keyBytes;
  out[5] = valueBytes;
  out.writeUInt32BE(sorted.length, 8);
  out.writeUInt32BE(labels.length, 12);
  let pos = HEADER_BYTES;
  for (const entry of sorted) {
    entry.key.copy(out, pos);
    if (withLabels) out.writeUInt16BE(labelIndex.get(entry.label), pos + keyBytes);
    pos += entrySize;
  }
  for (const bytes of labelBytes) {
    out[pos++] = bytes.length;
    bytes.copy(out, pos);
    pos += bytes.length;
  }
  return { bytes: out, entries: sorted.length, labels, collisions };
}

/**
 * Read the header and check the whole file is laid out as the format says.
 * Throws a plain message on anything off. Does not load the entries into objects.
 */
export function openTable(bytes, name = "table") {
  const fail = (why) => {
    throw new Error(`${name}: ${why}`);
  };
  if (bytes.length < HEADER_BYTES) fail(`only ${bytes.length} bytes, the header alone is ${HEADER_BYTES}`);
  if (bytes.toString("latin1", 0, 4) !== MAGIC) fail("does not start with TKL1");
  const keyBytes = bytes[4];
  const valueBytes = bytes[5];
  if (keyBytes !== KEY_BYTES) fail(`keyBytes is ${keyBytes}, expected ${KEY_BYTES}`);
  if (valueBytes !== 0 && valueBytes !== 2) fail(`valueBytes is ${valueBytes}, expected 0 or 2`);
  if (bytes.readUInt16BE(6) !== 0) fail("reserved field is not zero");
  const entryCount = bytes.readUInt32BE(8);
  const labelCount = bytes.readUInt32BE(12);
  const entrySize = keyBytes + valueBytes;
  const entriesEnd = HEADER_BYTES + entryCount * entrySize;
  // The same refusals as the app's TklTable.parse, so verify never passes a set the app refuses.
  if (entryCount === 0) fail("no entries");
  if (entriesEnd > bytes.length) fail(`${entryCount} entries do not fit in ${bytes.length} bytes`);
  if (valueBytes === 0 && labelCount !== 0) fail("labels present but valueBytes is 0");
  if (valueBytes === 2 && labelCount === 0) fail("values but no labels");
  if (labelCount > 65536) fail(`${labelCount} labels, more than a 2-byte index can reach`);
  if (labelCount > bytes.length - entriesEnd) fail(`${labelCount} labels do not fit in the bytes left`);
  const decoder = new TextDecoder("utf-8", { fatal: true });
  const labels = [];
  let pos = entriesEnd;
  for (let i = 0; i < labelCount; i++) {
    if (pos >= bytes.length) fail(`label ${i} is missing`);
    const length = bytes[pos++];
    if (length === 0) fail(`label ${i} is empty`);
    if (pos + length > bytes.length) fail(`label ${i} runs past the end`);
    let text;
    try {
      text = decoder.decode(bytes.subarray(pos, pos + length));
    } catch {
      fail(`label ${i} is not valid UTF-8`);
    }
    if (cleanLabel(text) === "") fail(`label ${i} has no visible text`);
    labels.push(text);
    pos += length;
  }
  if (pos !== bytes.length) fail(`${bytes.length - pos} stray bytes after the labels`);
  return { bytes, name, keyBytes, valueBytes, entryCount, labelCount, entrySize, labels };
}

/** The key of entry i as a Buffer view. */
export const keyAt = (table, i) => {
  const start = HEADER_BYTES + i * table.entrySize;
  return table.bytes.subarray(start, start + table.keyBytes);
};

/** Labels index of entry i (only for tables with values). */
export const valueAt = (table, i) => table.bytes.readUInt16BE(HEADER_BYTES + i * table.entrySize + table.keyBytes);

/**
 * Binary search for the text. Returns the label, true (a table without labels), or null.
 * Compares keys as unsigned bytes, as the app does.
 */
export function lookupText(table, text) {
  const key = keyOf(text, table.keyBytes);
  let lo = 0;
  let hi = table.entryCount - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >>> 1;
    const cmp = Buffer.compare(keyAt(table, mid), key);
    if (cmp === 0) {
      if (table.valueBytes === 0) return true;
      const index = valueAt(table, mid);
      if (index >= table.labels.length) throw new Error(`${table.name}: entry ${mid} points at label ${index}, only ${table.labels.length} exist`);
      return table.labels[index];
    }
    if (cmp < 0) lo = mid + 1;
    else hi = mid - 1;
  }
  return null;
}

/**
 * Check order and values: keys strictly ascending as unsigned bytes (so also no duplicates),
 * every label index in range. Returns a list of problems, empty when the table is sound.
 */
export function tableProblems(table) {
  const problems = [];
  for (let i = 1; i < table.entryCount; i++) {
    const cmp = Buffer.compare(keyAt(table, i - 1), keyAt(table, i));
    if (cmp === 0) problems.push(`${table.name}: entries ${i - 1} and ${i} have the same key`);
    else if (cmp > 0) problems.push(`${table.name}: entry ${i} sorts before entry ${i - 1}`);
    if (problems.length >= 5) return problems;
  }
  if (table.valueBytes === 2) {
    for (let i = 0; i < table.entryCount; i++) {
      if (valueAt(table, i) >= table.labelCount) {
        problems.push(`${table.name}: entry ${i} points at label ${valueAt(table, i)} of ${table.labelCount}`);
        if (problems.length >= 5) break;
      }
    }
  }
  return problems;
}
