// Fetch and read every source. Nothing here decides what goes into the lists; it returns what
// each source said, with counts of what it could not use. `fetchText(url, maxBytes)` is passed in,
// so tests run on fixtures and the real build on the network.

import { echapItems, parseEchapYaml, parseSamplesCsv } from "./echap.mjs";
import { MAX_STIX_BYTES, parseIndex, parseStix } from "./mvt.mjs";
import { FRESHNESS, MAX_BYTES, MAX_STIX_TOTAL, URLS } from "./sources.mjs";

/**
 * @typedef {{ id: string, pkg: Array<{text,label}>, cert: Array<{text,label}>, sha: Array<{text,label}>,
 *             hosts: string[], rejected: number, raw: number, notes: string[] }} Part
 */

const emptyPart = (id) => ({ id, pkg: [], cert: [], sha: [], hosts: [], rejected: 0, raw: 0, notes: [] });

/** @returns {Promise<Part>} */
export async function collectEchap(fetchText) {
  const [ioc, watchware, samples] = await Promise.all([
    fetchText(URLS.echapIoc, MAX_BYTES.yaml),
    fetchText(URLS.echapWatchware, MAX_BYTES.yaml),
    fetchText(URLS.echapSamples, MAX_BYTES.csv),
  ]);
  const items = echapItems({
    ioc: parseEchapYaml(ioc, "stalkerware", "ioc.yaml"),
    watchware: parseEchapYaml(watchware, "watchware", "watchware.yaml"),
    samples: parseSamplesCsv(samples, "samples.csv"),
  });
  return { ...emptyPart("echap"), pkg: items.pkg, cert: items.cert, sha: items.sha, rejected: items.rejected, raw: items.pkg.length + items.sha.length + items.cert.length + items.rejected, notes: items.notes };
}

/** @returns {Promise<Part[]>} one part for the MVT repository and one for Amnesty Tech's */
export async function collectMvt(fetchText) {
  const { files, skipped } = parseIndex(await fetchText(URLS.mvtIndex, MAX_BYTES.index));
  const parts = new Map([["mvt", emptyPart("mvt")], ["amnesty", emptyPart("amnesty")]]);
  parts.get("mvt").notes.push(...skipped.map((s) => `index: ${s}`));
  let total = 0;
  for (const file of files) {
    const text = await fetchText(file.url, MAX_STIX_BYTES);
    total += text.length;
    if (total > MAX_STIX_TOTAL) throw new Error(`the MVT files add up to more than ${MAX_STIX_TOTAL} bytes (at ${file.url})`);
    const bundle = parseStix(text, file.filePath);
    const part = parts.get(file.source);
    // A shape change would show as indicators the reader could not parse; a few odd ones are normal.
    if (bundle.unparsed > Math.max(2, bundle.indicators * 0.02)) throw new Error(`${file.filePath}: ${bundle.unparsed} of ${bundle.indicators} indicators have a pattern this reader does not know`);
    part.pkg.push(...bundle.pkg);
    part.cert.push(...bundle.cert);
    part.sha.push(...bundle.sha);
    part.hosts.push(...bundle.hosts);
    part.rejected += bundle.rejected;
    part.raw += bundle.pkg.length + bundle.cert.length + bundle.sha.length + bundle.hosts.length + bundle.rejected;
    part.notes.push(`${file.filePath}: ${bundle.hosts.length} hosts, ${bundle.pkg.length} packages, ${bundle.cert.length} certificates, ${bundle.sha.length} file hashes`);
  }
  return [parts.get("mvt"), parts.get("amnesty")];
}

/** A plain list, one host per line; blank lines and "#" lines are skipped. @returns {Promise<Part>} */
export async function collectHostList(fetchText, id, url) {
  const text = await fetchText(url, MAX_BYTES.hostList);
  const lines = text.split(/\r?\n/).map((l) => l.trim()).filter((l) => l !== "" && !l.startsWith("#"));
  if (lines.length === 0) throw new Error(`${url}: no hosts in the list`);
  return { ...emptyPart(id), hosts: lines, raw: lines.length };
}

/**
 * How old the upstream files are, from the repositories' commit lists. Returns warnings, never throws:
 * a stale or unreachable source is worth a loud line, but the last good data is still better than none.
 */
export async function freshnessWarnings(fetchText, now) {
  const warnings = [];
  for (const spec of FRESHNESS) {
    const url = `https://api.github.com/repos/${spec.owner}/${spec.repo}/commits?path=${encodeURIComponent(spec.path)}&per_page=1`;
    try {
      const commits = JSON.parse(await fetchText(url, 256 * 1024));
      const date = Date.parse(commits?.[0]?.commit?.committer?.date);
      if (Number.isNaN(date)) throw new Error("no commit date in the answer");
      const days = Math.floor((now.getTime() - date) / 86_400_000);
      if (days > spec.maxDays) warnings.push(`${spec.label}: last changed ${days} days ago (more than ${spec.maxDays}); the data may be stale`);
    } catch (error) {
      warnings.push(`${spec.label}: could not check its age (${error.message})`);
    }
  }
  return warnings;
}

/** All sources, in the order the tables use for ties: Echap, MVT, Amnesty, then the host lists. */
export async function collectAll(fetchText, { log = () => {} } = {}) {
  const echap = await collectEchap(fetchText);
  log(`Echap: ${echap.pkg.length} package rows, ${echap.sha.length} file hashes, ${echap.cert.length} certificate rows (SHA-256 or SHA-1)`);
  const [mvt, amnesty] = await collectMvt(fetchText);
  log(`MVT: ${mvt.hosts.length} hosts, ${mvt.pkg.length} packages, ${mvt.cert.length} certificates, ${mvt.sha.length} file hashes`);
  log(`Amnesty Tech: ${amnesty.hosts.length} hosts, ${amnesty.pkg.length} packages, ${amnesty.cert.length} certificates, ${amnesty.sha.length} file hashes`);
  const phishing = await collectHostList(fetchText, "phishing", URLS.phishing);
  log(`Phishing.Database: ${phishing.hosts.length} lines`);
  const certpl = await collectHostList(fetchText, "certpl", URLS.certPl);
  log(`CERT Polska: ${certpl.hosts.length} lines`);
  return [echap, mvt, amnesty, phishing, certpl];
}
