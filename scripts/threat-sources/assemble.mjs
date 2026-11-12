// From what the sources said to the four tables: app items are merged (the first source that names
// an item gives its label), hosts are normalised, checked against the keep-list, and cut to the
// size budget. Returns the files and a plain account of what was dropped and why.

import { CANARY, withCanary } from "./canary.mjs";
import { applyKeepList, buildKeeper, readHost } from "./hosts.mjs";
import { FILES, LIMITS } from "./manifest.mjs";
import { HEADER_BYTES, cleanLabel, keyOf, writeTable } from "./tkl.mjs";
import { HOST_PRIORITY } from "./sources.mjs";

/** Most host entries the table may hold at the size budget. */
export const maxHostEntries = (bytes = LIMITS.hostsBytes) => Math.floor((bytes - HEADER_BYTES) / 6);

const uniq = (items) => [...new Set(items)];

/**
 * @param {import("./collect.mjs").Part[]} parts
 * @param {{ keep: Map<string, boolean>, hostBudget?: number }} options
 * @returns {{ files: Array<{ name: string, bytes: Buffer, entries: number }>, hosts: string[], perSource: Map<string, object>, lines: string[] }}
 */
export function assemble(parts, { keep, hostBudget = LIMITS.hostsBytes }) {
  const lines = [];
  const perSource = new Map(parts.map((p) => [p.id, { id: p.id, pkg: 0, cert: 0, sha: 0, hosts: 0, rejected: p.rejected, raw: p.raw }]));

  const tables = {};
  for (const kind of ["pkg", "cert", "sha"]) {
    const entries = [];
    for (const part of parts) {
      for (const item of part[kind]) entries.push({ text: item.text, label: cleanLabel(item.label) });
      perSource.get(part.id)[kind] = uniq(part[kind].map((i) => i.text)).length;
    }
    tables[kind] = entries;
  }

  // Hosts: normalise and filter each source, then fill the table from the most trusted source down.
  const keeper = buildKeeper(keep);
  // One place in the budget is the canary's.
  const cap = maxHostEntries(hostBudget) - 1;
  const accepted = new Map();
  const ordered = [...parts.filter((p) => HOST_PRIORITY.includes(p.id))].sort((a, b) => HOST_PRIORITY.indexOf(a.id) - HOST_PRIORITY.indexOf(b.id));
  for (const part of ordered) {
    const stat = perSource.get(part.id);
    const valid = [];
    const invalid = [];
    let otherScripts = 0;
    let modeDependent = 0;
    for (const raw of part.hosts) {
      const read = readHost(raw);
      if (!read.host) {
        invalid.push(raw);
        continue;
      }
      valid.push(read.host);
      if (read.idna) otherScripts++;
      if (read.idna === "nontransitional") modeDependent++;
    }
    stat.rejected += invalid.length;
    const { kept, dropped } = applyKeepList(uniq(valid), keeper);
    const droppedTotal = [...dropped.values()].reduce((a, b) => a + b, 0);
    const fresh = kept.filter((host) => !accepted.has(keyOf(host, 6).toString("hex")));
    const room = Math.max(0, cap - accepted.size);
    let overBudget = 0;
    let take = fresh;
    if (fresh.length > room) {
      // Over budget: keep a pseudo-random part (the lowest keys), the same on every build.
      take = fresh.map((host) => [keyOf(host, 6).toString("hex"), host]).sort((a, b) => (a[0] < b[0] ? -1 : 1)).slice(0, room).map((e) => e[1]);
      overBudget = fresh.length - room;
    }
    for (const host of take) accepted.set(keyOf(host, 6).toString("hex"), host);
    stat.hosts = kept.length - overBudget;
    const top = [...dropped].sort((a, b) => b[1] - a[1]).slice(0, 5).map(([why, n]) => `${why} ${n}`).join(", ");
    lines.push(
      `hosts ${part.id}: ${part.hosts.length} read, ${invalid.length} not valid hosts${invalid.length ? ` (e.g. ${invalid.slice(0, 3).join(" | ")})` : ""}, ${otherScripts} converted to punycode (${modeDependent} with ß, ς or a joiner, kept in the app's nontransitional form), ${droppedTotal} dropped by the keep-list${top ? ` (${top})` : ""}, ${kept.length - fresh.length} already listed by an earlier source, ${overBudget} cut for the ${cap}-entry budget, ${take.length} added`,
    );
  }

  const hosts = [...accepted.values()];
  // Every table carries its canary; the optional file table is left out when nothing else is in it.
  const built = {
    pkg: writeTable({ keyBytes: 8, labelled: true, entries: withCanary("pkg", tables.pkg) }),
    cert: writeTable({ keyBytes: 8, labelled: true, entries: withCanary("cert", tables.cert) }),
    sha: tables.sha.length ? writeTable({ keyBytes: 8, labelled: true, entries: withCanary("sha", tables.sha) }) : null,
    hosts: writeTable({ keyBytes: 6, labelled: false, entries: withCanary("hosts", hosts.map((text) => ({ text }))) }),
  };
  lines.push(`canaries: ${CANARY.package}, ${CANARY.hex.slice(0, 8)}... and ${CANARY.host}; each table's entries include its one canary`);
  const files = [];
  for (const spec of FILES) {
    const table = built[spec.table];
    if (table === null && !spec.required) {
      lines.push(`${spec.name}: empty, left out`);
      continue;
    }
    if (table.collisions > 0) lines.push(`${spec.name}: ${table.collisions} entries share a key with another and were reduced to one`);
    files.push({ name: spec.name, bytes: table.bytes, entries: table.entries });
  }
  return { files, hosts, perSource, lines };
}
