// From what the sources said to the four tables: app items go through the app keep-lists and are
// merged (the first source that names an item gives its label); hosts are normalised, checked
// against the host keep-list and counted against the size budget. Nothing is cut silently: an
// over-budget host table and every keep-list hit are reported for the gates to judge.

import { CANARY, withCanary } from "./canary.mjs";
import { applyKeepList, buildKeeper, readHost } from "./hosts.mjs";
import { certRule, packageRule } from "./keep-apps.mjs";
import { nameUsedLabel } from "./labels.mjs";
import { FILES, LIMITS } from "./manifest.mjs";
import { HEADER_BYTES, KEY_BYTES, cleanLabel, keyOf, writeTable } from "./tkl.mjs";
import { HOST_PRIORITY } from "./sources.mjs";

/** Most host entries the table may hold at the size budget. */
export const maxHostEntries = (bytes = LIMITS.hostsBytes) => Math.floor((bytes - HEADER_BYTES) / KEY_BYTES);

/** App keep-lists that protect nothing, for tests that are about something else. */
export const NO_KEEP_APPS = Object.freeze({ packages: { exact: new Map(), prefixes: [], listed: new Set() }, certs: new Map() });

const uniq = (items) => [...new Set(items)];

/**
 * Fewest labels first, then the shortest names, then by name: short two-label names are the ones most likely to
 * be a real, popular site listed by mistake, so a person should look at them first.
 */
export const shortestHosts = (hosts, n = 50) =>
  [...hosts].sort((a, b) => a.split(".").length - b.split(".").length || a.length - b.length || (a < b ? -1 : a > b ? 1 : 0)).slice(0, n);

/**
 * @param {import("./collect.mjs").Part[]} parts
 * @param {{ keep: Map<string, boolean>, keepApps?: typeof NO_KEEP_APPS, hostBudget?: number }} options
 * @returns {{ files: Array<{ name: string, bytes: Buffer, entries: number }>, hosts: string[], certs: Array<{ text: string, label: string }>, perSource: Map<string, object>,
 *             lines: string[], appDrops: Array<{ table: string, text: string, label: string, source: string, rule: string, known: boolean }>,
 *             budget: { cap: number, wanted: number, over: Map<string, number> } }}
 */
export function assemble(parts, { keep, keepApps = NO_KEEP_APPS, hostBudget = LIMITS.hostsBytes }) {
  const lines = [];
  const perSource = new Map(parts.map((p) => [p.id, { id: p.id, pkg: 0, cert: 0, sha: 0, hosts: 0, rejected: p.rejected, raw: p.raw }]));

  // Apps: the keep-lists first, then merge.
  const appDrops = [];
  const renamed = new Set();
  const tables = {};
  for (const kind of ["pkg", "cert", "sha"]) {
    const entries = [];
    for (const part of parts) {
      const taken = [];
      for (const item of part[kind]) {
        let label = cleanLabel(item.label);
        const rule = kind === "pkg" ? packageRule(item.text, keepApps.packages) : kind === "cert" ? certRule(item.text, keepApps.certs) : null;
        if (rule?.listed) {
          label = nameUsedLabel(label);
          renamed.add(item.text);
        } else if (rule) {
          appDrops.push({ table: kind, text: item.text, label, source: part.id, rule: rule.rule, known: rule.known });
          continue;
        }
        entries.push({ text: item.text, label });
        taken.push(item.text);
      }
      perSource.get(part.id)[kind] = uniq(taken).length;
    }
    tables[kind] = entries;
  }
  const distinct = uniq(appDrops.map((d) => `${d.table} ${d.text}`)).length;
  lines.push(`apps: ${distinct} distinct entries dropped by the app keep-lists (${appDrops.length} rows), ${renamed.size} packages kept under a system prefix as "name used by"`);

  // Hosts: normalise and filter each source, then add from the most trusted source down.
  const keeper = buildKeeper(keep);
  // One place in the budget is the canary's.
  const cap = maxHostEntries(hostBudget) - 1;
  const accepted = new Map();
  const over = new Map();
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
    const fresh = kept.filter((host) => !accepted.has(keyOf(host).toString("hex")));
    const room = Math.max(0, cap - accepted.size);
    if (fresh.length > room) over.set(part.id, fresh.length - room);
    for (const host of fresh) accepted.set(keyOf(host).toString("hex"), host);
    stat.hosts = kept.length;
    const top = [...dropped].sort((a, b) => b[1] - a[1]).slice(0, 5).map(([why, n]) => `${why} ${n}`).join(", ");
    lines.push(
      `hosts ${part.id}: ${part.hosts.length} read, ${invalid.length} not valid hosts${invalid.length ? ` (e.g. ${invalid.slice(0, 3).join(" | ")})` : ""}, ${otherScripts} converted to punycode (${modeDependent} with ß, ς or a joiner, kept in the app's nontransitional form), ${droppedTotal} dropped by the keep-list${top ? ` (${top})` : ""}, ${kept.length - fresh.length} already listed by an earlier source, ${fresh.length} added`,
    );
  }

  const hosts = [...accepted.values()];
  lines.push(`hosts: ${hosts.length} of a ${cap}-entry budget`);
  // Every table carries its canary; the optional file table is left out when nothing else is in it.
  const built = {
    pkg: writeTable({ labelled: true, entries: withCanary("pkg", tables.pkg) }),
    cert: writeTable({ labelled: true, entries: withCanary("cert", tables.cert) }),
    sha: tables.sha.length ? writeTable({ labelled: true, entries: withCanary("sha", tables.sha) }) : null,
    hosts: writeTable({ labelled: false, entries: withCanary("hosts", hosts.map((text) => ({ text }))) }),
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
  return { files, hosts, certs: tables.cert, perSource, lines, appDrops, budget: { cap, wanted: hosts.length, over } };
}
