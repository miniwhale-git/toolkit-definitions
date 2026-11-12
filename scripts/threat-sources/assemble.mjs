// From what the sources said to the four tables: app items go through the app keep-lists and are
// merged (the first source that names an item gives its label); hosts go through host-table.mjs
// (keep-list, short names, growth hold, budget). Nothing is cut silently: every keep-list hit,
// automatic listing, hold and trim is returned for the gates and the report.

import { CANARY, withCanary } from "./canary.mjs";
import { buildHostTable } from "./host-table.mjs";
import { certRule, packageRule } from "./keep-apps.mjs";
import { nameUsedLabel } from "./labels.mjs";
import { FILES, LIMITS } from "./manifest.mjs";
import { HEADER_BYTES, KEY_BYTES, cleanLabel, writeTable } from "./tkl.mjs";

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
 * @param {{ keep: Map<string, boolean>, keepApps?: typeof NO_KEEP_APPS, hostBudget?: number,
 *           previous?: { hosts: object | null, entries: Map<string, number> } | null, allowGrowth?: boolean }} options
 * @returns {{ files: Array<{ name: string, bytes: Buffer, entries: number }>, hosts: string[], certs: Array<{ text: string, label: string }>, perSource: Map<string, object>,
 *             lines: string[], appDrops: Array<{ table: string, text: string, label: string, source: string, rule: string, known: boolean }>,
 *             autoListed: Array<{ text: string, label: string, source: string, rule: string }>,
 *             budget: { cap: number, wanted: number, trims: Array<{ id: string, wanted: number, cut: number }> },
 *             short: Array<{ id: string, rule: string, host: string }>, shortKept: Array<{ id: string, exception: string, host: string }>, held: Array<object> }}
 */
export function assemble(parts, { keep, keepApps = NO_KEEP_APPS, hostBudget = LIMITS.hostsBytes, previous = null, allowGrowth = false }) {
  const lines = [];
  const perSource = new Map(parts.map((p) => [p.id, { id: p.id, pkg: 0, cert: 0, sha: 0, hosts: 0, rejected: p.rejected, raw: p.raw }]));

  // Apps: the keep-lists first, then merge.
  const appDrops = [];
  const autoListed = new Map();
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
          if (rule.auto && !autoListed.has(item.text)) autoListed.set(item.text, { text: item.text, label, source: part.id, rule: rule.rule });
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
  lines.push(`apps: ${distinct} distinct entries dropped by the app keep-lists (${appDrops.length} rows), ${renamed.size} packages under a system prefix kept as "name used by" (${autoListed.size} of them listed automatically)`);
  for (const a of autoListed.values()) lines.push(`listed automatically: package ${a.text} as "${a.label}" (from ${a.source}; ${a.rule})`);

  // Hosts. One place in the budget is the canary's.
  const cap = maxHostEntries(hostBudget) - 1;
  const appEntries = new Map([...perSource].map(([id, s]) => [id, s.pkg + s.cert + s.sha]));
  const host = buildHostTable(parts, { keep, cap, previous, appEntries, allowGrowth });
  for (const [id, n] of host.counts) perSource.get(id).hosts = n;
  for (const [id, n] of host.rejected) perSource.get(id).rejected += n;
  lines.push(...host.lines);

  // Every table carries its canary; the optional file table is left out when nothing else is in it.
  const built = {
    pkg: writeTable({ labelled: true, entries: withCanary("pkg", tables.pkg) }),
    cert: writeTable({ labelled: true, entries: withCanary("cert", tables.cert) }),
    sha: tables.sha.length ? writeTable({ labelled: true, entries: withCanary("sha", tables.sha) }) : null,
    hosts: writeTable({ labelled: false, entries: withCanary("hosts", host.hosts.map((text) => ({ text }))) }),
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
  return {
    files,
    hosts: host.hosts,
    certs: tables.cert,
    perSource,
    lines,
    appDrops,
    autoListed: [...autoListed.values()],
    budget: { cap, wanted: host.wanted, trims: host.trims },
    short: host.short,
    shortKept: host.shortKept,
    held: host.held,
  };
}
