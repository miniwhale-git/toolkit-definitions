// Echap stalkerware-indicators: ioc.yaml (stalkerware), watchware.yaml (apps that can be used to
// watch someone) and samples.csv (APK hashes). Licence CC-BY-4.0 per the project's README.
//
// What we take: package names (apps-pkg), APK SHA-256 hashes (apps-sha) and certificate
// fingerprints (apps-cert). Echap lists certificates as SHA-1 (40 hex); apps-cert takes both the
// SHA-256 and the SHA-1 form, each as lower-case hex text. Labels read "Name (stalkerware)" or
// "Name (watchware)", or "Stalkerware" / "Monitoring app" when the name does not pass the label
// filter (labels.mjs). Where one package is in both files the watchware label wins: it is the
// softer claim, and Echap moved those apps there on purpose.

import { threatLabel } from "./labels.mjs";
import { parseYaml } from "./yaml.mjs";

export const PACKAGE_NAME = /^[A-Za-z0-9_]+(\.[A-Za-z0-9_]+)+$/;
const HEX64 = /^[0-9a-fA-F]{64}$/;
const HEX40 = /^[0-9a-fA-F]{40}$/;

function listOf(value, what, where) {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value) || value.some((v) => typeof v !== "string")) throw new Error(`${where}: ${what} is not a list of text values`);
  return value;
}

/**
 * Read one Echap YAML file.
 * @returns {{ apps: Array<{ name: string, type: string, packages: string[], sha1: string[], sha256: string[] }> }}
 */
export function parseEchapYaml(text, expectedType, label) {
  const doc = parseYaml(text, label);
  if (!Array.isArray(doc) || doc.length === 0) throw new Error(`${label}: expected a list of apps, found ${doc === null ? "nothing" : typeof doc}`);
  const apps = doc.map((entry, i) => {
    const where = `${label} entry ${i + 1}`;
    if (entry === null || typeof entry !== "object" || Array.isArray(entry)) throw new Error(`${where}: not a mapping`);
    if (typeof entry.name !== "string" || entry.name === "") throw new Error(`${where}: no name`);
    if (entry.type !== expectedType) throw new Error(`${where} (${entry.name}): type is "${entry.type}", expected "${expectedType}"`);
    const certs = listOf(entry.certificates, "certificates", where);
    const sha1 = [];
    const sha256 = [];
    for (const cert of certs) {
      if (HEX64.test(cert)) sha256.push(cert.toLowerCase());
      else if (HEX40.test(cert)) sha1.push(cert.toLowerCase());
      else throw new Error(`${where} (${entry.name}): certificate "${cert}" is neither SHA-1 nor SHA-256 hex`);
    }
    return { name: entry.name, type: entry.type, packages: listOf(entry.packages, "packages", where), sha1, sha256 };
  });
  return { apps };
}

/** samples.csv: SHA256,Package Name,Certificate,Version,App. Plain fields only; a quote or a short row stops the build. */
export function parseSamplesCsv(text, label) {
  const lines = text.split(/\r?\n/).filter((l) => l !== "");
  if (lines.length < 2) throw new Error(`${label}: no rows`);
  if (lines[0] !== "SHA256,Package Name,Certificate,Version,App") throw new Error(`${label}: unexpected header "${lines[0]}"`);
  return lines.slice(1).map((line, i) => {
    if (line.includes('"')) throw new Error(`${label} row ${i + 2}: quoted fields are not supported`);
    const f = line.split(",");
    if (f.length !== 5) throw new Error(`${label} row ${i + 2}: ${f.length} fields, expected 5`);
    if (!HEX64.test(f[0])) throw new Error(`${label} row ${i + 2}: "${f[0]}" is not a SHA-256`);
    if (f[4].trim() === "") throw new Error(`${label} row ${i + 2}: no app name`);
    return { sha256: f[0].toLowerCase(), packageName: f[1].trim(), cert: f[2].trim().toLowerCase(), app: f[4].trim() };
  });
}

const labelFor = (name, type) => threatLabel(name, type);

/**
 * Merge the three files into table items. Watchware is applied first so its labels win.
 * @returns {{ pkg: Array<{text,label}>, sha: Array<{text,label}>, cert: Array<{text,label}>, rejected: number, notes: string[] }}
 */
export function echapItems({ ioc, watchware, samples }) {
  const pkg = [];
  const sha = [];
  const cert = [];
  let rejected = 0;
  let noPackage = 0;
  const sha1Seen = new Set();
  const typeOfApp = new Map();
  for (const file of [watchware, ioc]) {
    for (const app of file.apps) {
      if (!typeOfApp.has(app.name.toLowerCase())) typeOfApp.set(app.name.toLowerCase(), app.type);
      const label = labelFor(app.name, app.type);
      for (const name of app.packages) {
        if (PACKAGE_NAME.test(name)) pkg.push({ text: name, label });
        else rejected++;
      }
      for (const hash of app.sha256) cert.push({ text: hash, label });
      for (const hash of app.sha1) {
        sha1Seen.add(hash);
        cert.push({ text: hash, label });
      }
    }
  }
  for (const row of samples) {
    const type = typeOfApp.get(row.app.toLowerCase()) ?? "stalkerware";
    const label = labelFor(row.app, type);
    sha.push({ text: row.sha256, label });
    // Many sample rows have no package name; that is not an error.
    if (row.packageName === "") noPackage++;
    else if (PACKAGE_NAME.test(row.packageName)) pkg.push({ text: row.packageName, label });
    else rejected++;
    if (HEX40.test(row.cert)) sha1Seen.add(row.cert);
    if (HEX40.test(row.cert) || HEX64.test(row.cert)) cert.push({ text: row.cert, label });
  }
  const notes = [`${noPackage} sample rows have no package name`, `${sha1Seen.size} distinct certificate fingerprints are SHA-1; apps-cert holds them beside the SHA-256 ones`];
  return { pkg, sha, cert, rejected, notes };
}
