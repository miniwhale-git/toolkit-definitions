// The host table from the host sources, in four steps, each counted:
//   1. every source's hosts normalised and checked against the keep-list (shorteners included);
//   2. short bare domains dropped from the bulk lists (hosts.mjs shortNameRule);
//   3. a source that more than doubled since the previous set is held at its previous data;
//   4. the sources added most trusted first; over the size budget, the cut comes from the least
//      trusted source, keeping its hosts with the lowest keys.
// Nothing is cut silently: every drop, hold and trim is returned for the gates and the report.

import { applyKeepList, buildKeeper, readHost, shortNameRule } from "./hosts.mjs";
import { HOST_PRIORITY, MAX_SOURCE_GROWTH, SHORT_NAME_SOURCES } from "./sources.mjs";
import { keyOf, lookupText } from "./tkl.mjs";

const uniq = (items) => [...new Set(items)];
const hexKey = (host) => keyOf(host).toString("hex");

/**
 * @param {import("./collect.mjs").Part[]} parts every part; only those in HOST_PRIORITY give hosts
 * @param {{ keep: Map<string, boolean>, cap: number, previous?: { hosts: object | null, entries: Map<string, number> } | null,
 *           appEntries?: Map<string, number>, allowGrowth?: boolean, shortSources?: string[], maxGrowth?: number }} options
 *   previous: the previous set's host table (as openTable gives it) and each source's entries in its manifest.
 *   appEntries: each source's app entries in this build, so its whole count compares with the manifest's.
 * @returns {{ hosts: string[], counts: Map<string, number>, lines: string[], wanted: number,
 *             short: Array<{ id: string, rule: string, host: string }>, held: Array<{ id: string, before: number, now: number, kept: number, allowed: boolean }>,
 *             trims: Array<{ id: string, wanted: number, cut: number }>, rejected: Map<string, number> }}
 */
export function buildHostTable(parts, { keep, cap, previous = null, appEntries = new Map(), allowGrowth = false, shortSources = SHORT_NAME_SOURCES, maxGrowth = MAX_SOURCE_GROWTH }) {
  const lines = [];
  const keeper = buildKeeper(keep);
  const ordered = parts.filter((p) => HOST_PRIORITY.includes(p.id)).sort((a, b) => HOST_PRIORITY.indexOf(a.id) - HOST_PRIORITY.indexOf(b.id));

  // 1. Normalise and apply the keep-list.
  const kept = new Map();
  const notes = new Map();
  const rejected = new Map();
  for (const part of ordered) {
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
    rejected.set(part.id, invalid.length);
    const filtered = applyKeepList(uniq(valid), keeper);
    kept.set(part.id, filtered.kept);
    const droppedTotal = [...filtered.dropped.values()].reduce((a, b) => a + b, 0);
    const top = [...filtered.dropped].sort((a, b) => b[1] - a[1]).slice(0, 5).map(([why, n]) => `${why} ${n}`).join(", ");
    notes.set(
      part.id,
      `${part.hosts.length} read, ${invalid.length} not valid hosts${invalid.length ? ` (e.g. ${invalid.slice(0, 3).join(" | ")})` : ""}, ${otherScripts} converted to punycode (${modeDependent} with ß, ς or a joiner, kept in the app's nontransitional form), ${droppedTotal} dropped by the keep-list${top ? ` (${top})` : ""}`,
    );
  }

  // 2. Short bare domains, from the bulk lists only. A name two sources list is less likely a mistake.
  const listedBy = new Map();
  for (const hosts of kept.values()) for (const host of hosts) listedBy.set(host, (listedBy.get(host) ?? 0) + 1);
  const short = [];
  for (const [id, hosts] of kept) {
    if (!shortSources.includes(id)) continue;
    kept.set(
      id,
      hosts.filter((host) => {
        const rule = shortNameRule(host, listedBy.get(host));
        if (rule) short.push({ id, rule, host });
        return rule === null;
      }),
    );
  }

  // 3. Growth: a source that more than doubled keeps only what the previous set already listed.
  const held = [];
  for (const [id, hosts] of kept) {
    const before = previous?.entries.get(id) ?? 0;
    const now = (appEntries.get(id) ?? 0) + hosts.length;
    if (before <= 0 || now <= before * (1 + maxGrowth)) continue;
    if (allowGrowth || !previous.hosts) {
      held.push({ id, before, now, kept: hosts.length, allowed: true });
      continue;
    }
    const stays = hosts.filter((host) => lookupText(previous.hosts, host) !== null);
    kept.set(id, stays);
    held.push({ id, before, now, kept: stays.length, allowed: false });
  }

  // 4. The budget, most trusted source first; any cut comes from the last ones.
  const accepted = new Map();
  const counts = new Map();
  const trims = [];
  let wanted = 0;
  for (const part of ordered) {
    const hosts = kept.get(part.id);
    let fresh = hosts.filter((host) => !accepted.has(hexKey(host)));
    wanted += fresh.length;
    const room = Math.max(0, cap - accepted.size);
    let cut = 0;
    if (fresh.length > room) {
      const byKey = fresh.map((host) => [hexKey(host), host]).sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
      cut = fresh.length - room;
      trims.push({ id: part.id, wanted: fresh.length, cut });
      fresh = byKey.slice(0, room).map(([, host]) => host);
    }
    for (const host of fresh) accepted.set(hexKey(host), host);
    counts.set(part.id, hosts.length - cut);
    const shortHere = short.filter((s) => s.id === part.id);
    const hold = held.find((h) => h.id === part.id && !h.allowed);
    lines.push(
      `hosts ${part.id}: ${notes.get(part.id)}, ${shortHere.length} short bare domains dropped${hold ? `, HELD at its previous data (${hold.before} -> ${hold.now} entries; ${hold.kept} hosts already listed kept)` : ""}, ${hosts.length - fresh.length - cut} already listed by an earlier source, ${fresh.length} added${cut ? `, ${cut} CUT to fit the budget` : ""}`,
    );
  }
  const hosts = [...accepted.values()];
  lines.push(`hosts: ${hosts.length} of a ${cap}-entry budget${trims.length ? `; ${wanted - hosts.length} cut` : ""}`);
  return { hosts, counts, lines, wanted, short, held, trims, rejected };
}
