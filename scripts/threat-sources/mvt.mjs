// Mobile Verification Toolkit indicators (https://github.com/mvt-project/mvt-indicators).
// The repository's own index (indicators.yaml) names the STIX2 files; only those are fetched, and
// only from repositories whose licence was read and recorded in REPOS below. A new repository in
// the index is skipped and said so, never followed.
//
// What we take from a bundle: app:id (package names), app:cert.sha256 and app:cert.sha1 (certificates),
// file:hashes.sha256 (APK hashes) and domain-name:value (hosts). IP addresses, file paths, process
// names and the rest do not fit our tables. Labels name the campaign: "Predator (spyware)".

import { threatLabel } from "./labels.mjs";
import { parseYaml } from "./yaml.mjs";

/** Repositories whose licence was read: id of the source row they count under, and the licence. */
export const REPOS = {
  "mvt-project/mvt-indicators": { source: "mvt", licence: "MIT" },
  "AmnestyTech/investigations": { source: "amnesty", licence: "CC-BY-2.0" },
};

/** The Echap bundle in the index is the same data as ioc.yaml, which is read directly. */
const READ_DIRECTLY = new Set(["AssoEchap/stalkerware-indicators"]);

export const MAX_STIX_BYTES = 8 * 1024 * 1024;

const SAFE = /^[A-Za-z0-9._-]+$/;
const SAFE_PATH = /^[A-Za-z0-9._-]+(\/[A-Za-z0-9._-]+)*\.stix2$/;

/** The index as a list of files to fetch, plus the entries left out and why. */
export function parseIndex(text, label = "indicators.yaml") {
  const doc = parseYaml(text, label);
  const list = doc?.indicators;
  if (!Array.isArray(list) || list.length === 0) throw new Error(`${label}: no "indicators" list`);
  const files = [];
  const skipped = [];
  for (const [i, entry] of list.entries()) {
    const where = `${label} entry ${i + 1}`;
    if (entry === null || typeof entry !== "object") throw new Error(`${where}: not a mapping`);
    if (entry.type !== "github" || typeof entry.github !== "object" || entry.github === null) {
      skipped.push(`${entry.name ?? where}: type "${entry.type}" is not followed`);
      continue;
    }
    const { owner, repo, branch, path: filePath } = entry.github;
    for (const [k, v] of Object.entries({ owner, repo, branch })) {
      if (typeof v !== "string" || !SAFE.test(v)) throw new Error(`${where}: github.${k} "${v}" is not a plain name`);
    }
    if (typeof filePath !== "string" || !SAFE_PATH.test(filePath) || filePath.includes("..")) {
      throw new Error(`${where}: github.path "${filePath}" is not a plain .stix2 path`);
    }
    const id = `${owner}/${repo}`;
    if (READ_DIRECTLY.has(id)) {
      skipped.push(`${entry.name}: same data as the Echap files, read directly`);
      continue;
    }
    if (!REPOS[id]) {
      skipped.push(`${entry.name}: ${id} has no recorded licence`);
      continue;
    }
    files.push({ name: String(entry.name), repo: id, source: REPOS[id].source, filePath, url: `https://raw.githubusercontent.com/${id}/${branch}/${filePath}` });
  }
  return { files, skipped };
}

/** Full labels for names whose plain form reads badly. Each passes the label filter (a test checks). */
export const LABELS = {
  RCSLab: "RCS Lab (spyware)",
  OperationTriangulation: "Operation Triangulation (spyware)",
  WyrmSpy_DragonEgg: "WyrmSpy and DragonEgg (spyware)",
  MercenarySpywareCampaign: "Mercenary campaign (spyware)",
  Cellebrite: "Cellebrite (forensic tool)",
};

/** "<name> (spyware)", or "Spyware" when the name does not pass the label filter (labels.mjs). */
export const campaignLabel = (malwareName) => LABELS[malwareName] ?? threatLabel(String(malwareName).replace(/_/g, " "), "spyware");

const PATTERN = /^\[([a-z0-9-]+):([A-Za-z0-9._-]+)\s*=\s*'([^'\\]*)'\]$/;
const WANTED = { "app:id": "pkg", "app:cert.sha256": "cert", "app:cert.sha1": "cert", "file:hashes.sha256": "sha", "domain-name:value": "host" };
/** What a value of each hashed kind must look like once lower-cased. */
const HEX = { "app:cert.sha256": /^[0-9a-f]{64}$/, "app:cert.sha1": /^[0-9a-f]{40}$/, "file:hashes.sha256": /^[0-9a-f]{64}$/ };

/**
 * Read one STIX2 bundle.
 * @returns {{ pkg: Array<{text,label}>, cert: Array<{text,label}>, sha: Array<{text,label}>, hosts: string[], rejected: number, unparsed: number, indicators: number }}
 */
export function parseStix(text, label) {
  let bundle;
  try {
    bundle = JSON.parse(text);
  } catch (error) {
    throw new Error(`${label}: not JSON (${error.message})`);
  }
  if (bundle?.type !== "bundle" || !Array.isArray(bundle.objects)) throw new Error(`${label}: not a STIX bundle`);
  const malware = new Map();
  const links = new Map();
  for (const object of bundle.objects) {
    if (object.type === "malware" && typeof object.name === "string") malware.set(object.id, object.name);
    if (object.type === "relationship" && object.relationship_type === "indicates") links.set(object.source_ref, object.target_ref);
  }
  const only = malware.size === 1 ? [...malware.values()][0] : null;
  const out = { pkg: [], cert: [], sha: [], hosts: [], rejected: 0, unparsed: 0, indicators: 0 };
  for (const object of bundle.objects) {
    if (object.type !== "indicator") continue;
    out.indicators++;
    const match = typeof object.pattern === "string" ? object.pattern.match(PATTERN) : null;
    if (!match) {
      out.unparsed++;
      continue;
    }
    const field = `${match[1]}:${match[2]}`;
    const kind = WANTED[field];
    if (!kind) continue;
    const value = match[3];
    if (kind === "host") {
      out.hosts.push(value);
      continue;
    }
    const name = malware.get(links.get(object.id)) ?? only;
    if (!name) throw new Error(`${label}: indicator ${object.id} has no malware and the bundle has ${malware.size}`);
    const item = { text: kind === "pkg" ? value : value.toLowerCase(), label: campaignLabel(name) };
    if (kind !== "pkg" && !HEX[field].test(item.text)) out.rejected++;
    else if (kind === "pkg" && !/^[A-Za-z0-9_]+(\.[A-Za-z0-9_]+)+$/.test(value)) out.rejected++;
    else out[kind].push(item);
  }
  return out;
}
