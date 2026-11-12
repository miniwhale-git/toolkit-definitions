// The keep-lists for the app tables: packages (keep-packages.txt) and signing certificates
// (keep-certs.txt) that must never be listed, however the sources look. One upstream commit that
// adds com.whatsapp or a phone maker's certificate would otherwise reach every phone the next day.
//
// keep-packages.txt, one entry per line ("#" starts a comment):
//   com.whatsapp               this exact package is never listed
//   com.android.*              a system prefix: a package under it that no exact line names is listed,
//                              labelled "... (name used by stalkerware)", and printed. Stalkerware hides
//                              behind such names; a real system app has an exact line.
//   com.android.core.mngi listed   the same, already reviewed.
// keep-certs.txt: the lower-case hex SHA-1 (40) or SHA-256 (64) of a certificate's DER bytes.
// Either file may mark an entry "known": a source is known to list it, so dropping it is expected.
// Every other exact or certificate hit is new; the build fails when one run drops more than
// MAX_NEW_HITS of those. A listing under a prefix never counts toward that.

import { readFileSync } from "node:fs";
import path from "node:path";

export const KEEP_PACKAGES_FILE = path.join(import.meta.dirname, "keep-packages.txt");
export const KEEP_CERTS_FILE = path.join(import.meta.dirname, "keep-certs.txt");

/** More new keep-list hits than this in one build look like a tampered source: the build stops. */
export const MAX_NEW_HITS = 3;

const HEX = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
/** A package name, or the single word "android" (the framework itself). */
const NAME = /^[A-Za-z0-9_]+(\.[A-Za-z0-9_]+)*$/;

function lines(text, label, each) {
  text.split(/\r?\n/).forEach((line, i) => {
    const content = line.replace(/#.*/, "").trim();
    if (content) each(content.split(/\s+/), `${label} line ${i + 1}`, content);
  });
}

/**
 * @returns {{ exact: Map<string, { known: boolean }>, prefixes: string[], listed: Set<string> }}
 */
export function parseKeepPackages(text, label = "keep-packages.txt") {
  const exact = new Map();
  const prefixes = [];
  const listed = new Set();
  lines(text, label, ([name, flag, ...rest], where, content) => {
    const bad = () => {
      throw new Error(`${where}: "${content}" is not "package", "package known", "prefix.*" or "package listed"`);
    };
    if (rest.length > 0) bad();
    if (name.endsWith(".*")) {
      const stem = name.slice(0, -2);
      if (flag !== undefined || !NAME.test(stem)) bad();
      const prefix = `${stem}.`;
      if (prefixes.includes(prefix)) throw new Error(`${where}: ${name} is listed twice`);
      prefixes.push(prefix);
      return;
    }
    if (!NAME.test(name) || (flag !== undefined && flag !== "known" && flag !== "listed")) bad();
    if (exact.has(name) || listed.has(name)) throw new Error(`${where}: ${name} is listed twice`);
    if (flag === "listed") listed.add(name);
    else exact.set(name, { known: flag === "known" });
  });
  for (const name of listed) {
    if (!prefixes.some((p) => name.startsWith(p))) throw new Error(`${label}: ${name} is marked listed but is under no protected prefix`);
  }
  return { exact, prefixes, listed };
}

/** @returns {Map<string, { known: boolean }>} */
export function parseKeepCerts(text, label = "keep-certs.txt") {
  const certs = new Map();
  lines(text, label, ([hex, flag, ...rest], where, content) => {
    if (!HEX.test(hex) || rest.length > 0 || (flag !== undefined && flag !== "known")) throw new Error(`${where}: "${content}" is not "hex" or "hex known" (lower-case SHA-1 or SHA-256)`);
    if (certs.has(hex)) throw new Error(`${where}: ${hex} is listed twice`);
    certs.set(hex, { known: flag === "known" });
  });
  return certs;
}

export const loadKeepPackages = (file = KEEP_PACKAGES_FILE) => parseKeepPackages(readFileSync(file, "utf8"), path.basename(file));
export const loadKeepCerts = (file = KEEP_CERTS_FILE) => parseKeepCerts(readFileSync(file, "utf8"), path.basename(file));
export const loadKeepApps = () => ({ packages: loadKeepPackages(), certs: loadKeepCerts() });

/**
 * What the keep-list says about a package: null (nothing), { rule, known } (an exact line: drop it), or
 * { listed: true, auto, rule } (under a system prefix: list it as "name used by ..."; `auto` when no
 * "listed" line names it yet, so a person should look at it).
 */
export function packageRule(name, packages) {
  const exact = packages.exact.get(name);
  if (exact) return { rule: `keep ${name}`, known: exact.known };
  const prefix = packages.prefixes.find((p) => name.startsWith(p));
  if (packages.listed.has(name)) return { listed: true, auto: false, rule: `listed under ${prefix}*` };
  return prefix ? { listed: true, auto: true, rule: `under ${prefix}*` } : null;
}

/** Why a certificate may not be listed: null, or { rule, known }. */
export function certRule(hex, certs) {
  const hit = certs.get(hex);
  return hit ? { rule: `keep ${hex}`, known: hit.known } : null;
}
