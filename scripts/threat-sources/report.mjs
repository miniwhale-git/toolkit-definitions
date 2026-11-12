// The short Markdown report of one build: what a person should look at, even when every gate passed.
// The workflow adds it to the run summary and, when `notify` is not empty, puts it in the "Daily lists"
// issue. Text that came from a source is made plain: no backticks, no "@", no line breaks, so it cannot
// break out of the page's formatting or mention anyone.

import { lookupText } from "./tkl.mjs";

/** The largest report: an issue body holds 65,536 characters. */
export const MAX_REPORT = 60_000;

/** Source text made safe for the issue and the run summary. */
export const plain = (text) => String(text).replace(/[`@]/g, "").replace(/[\r\n\t]+/g, " ");

/**
 * @param {{ version: number, ok: boolean, results: Array<{ gate: string, ok: boolean, detail: string }>,
 *           appDrops: Array<{ table: string, text: string, label: string, source: string, rule: string, known: boolean }>,
 *           newCerts: Map<string, string> | null, autoListed: Array<{ text: string, label: string, source: string, rule: string }>,
 *           previousPkg: object | null, budget: { trims: Array<{ id: string, wanted: number, cut: number }> },
 *           held: Array<{ id: string, before: number, now: number, kept: number, allowed: boolean }>,
 *           short: Array<{ id: string, rule: string, host: string }>, shortest: string[], warnings?: string[] }} input
 * @returns {{ markdown: string, notify: string[] }} notify: why a person should look, empty when nothing needs it
 */
export function buildReport({ version, ok, results, appDrops, newCerts, autoListed, previousPkg, budget, held, short, shortest, warnings = [] }) {
  const hits = new Map();
  for (const d of appDrops) if (!hits.has(`${d.table} ${d.text}`)) hits.set(`${d.table} ${d.text}`, d);
  const freshHits = [...hits.values()].filter((d) => !d.known);
  const newAuto = autoListed.filter((a) => previousPkg && lookupText(previousPkg, a.text) === null);
  const holds = held.filter((h) => !h.allowed);

  const notify = [];
  if (!ok) notify.push("a gate failed, nothing was published");
  if (freshHits.length) notify.push(`${freshHits.length} new keep-list hits dropped`);
  if (newCerts?.size) notify.push(`${newCerts.size} new certificate entries`);
  if (newAuto.length) notify.push(`${newAuto.length} new packages listed under a system prefix`);
  if (budget.trims.length) notify.push("hosts trimmed to fit the budget");
  if (holds.length) notify.push(`${holds.map((h) => h.id).join(", ")} held at the previous data`);

  const out = [];
  out.push(`<!-- notify: ${notify.length ? "yes" : "no"} -->`);
  out.push(`## Daily lists: v${version} ${ok ? "built" : "NOT published"}`);
  out.push("");
  out.push(notify.length ? `Needs a look: ${notify.join("; ")}.` : "Nothing needs a look.");
  out.push("");
  out.push("### Gates");
  for (const r of results) out.push(`- ${r.ok ? "PASS" : "**FAIL**"} ${r.gate}: ${plain(r.detail).slice(0, 600)}`);
  for (const w of warnings) out.push(`- WARNING ${plain(w)}`);

  out.push("", "### App keep-list hits (dropped)");
  if (hits.size === 0) out.push("None.");
  for (const d of hits.values()) out.push(`- ${d.table === "pkg" ? "package" : "certificate"} ${plain(d.text)}: ${plain(d.label)} (from ${plain(d.source)}; ${plain(d.rule)}${d.known ? ", known" : ", NEW"})`);

  out.push("", "### New certificate entries");
  if (newCerts === null) out.push("No previous set to compare with.");
  else if (newCerts.size === 0) out.push("None.");
  else for (const [hex, label] of newCerts) out.push(`- ${plain(hex)} ${plain(label)}`);

  out.push("", "### Packages listed under a system prefix (as \"name used by\")");
  if (autoListed.length === 0) out.push("None beyond the reviewed ones in keep-packages.txt.");
  for (const a of autoListed) out.push(`- ${plain(a.text)} as ${plain(a.label)} (from ${plain(a.source)})${newAuto.includes(a) ? ", NEW since the previous set" : ""}`);

  out.push("", "### Hosts");
  if (budget.trims.length === 0) out.push("- Budget: everything fit.");
  for (const t of budget.trims) out.push(`- TRIMMED ${t.cut} of ${t.wanted} new hosts from ${t.id} to fit the budget (lowest keys kept).`);
  for (const h of held) out.push(`- ${h.id}: ${h.before} -> ${h.now} entries${h.allowed ? ", published (allow_growth)" : `, HELD at its previous data (${h.kept} hosts kept). Run with allow_growth if it really grew.`}`);
  const byRule = new Map();
  for (const s of short) byRule.set(`${s.rule} (${s.id})`, (byRule.get(`${s.rule} (${s.id})`) ?? 0) + 1);
  out.push(`- Short bare domains dropped: ${short.length}${byRule.size ? `; ${[...byRule].map(([k, n]) => `${k} ${n}`).join(", ")}` : ""}.`);
  if (short.length) out.push(`- For example: ${short.slice(0, 10).map((s) => plain(s.host)).join(" ")}`);
  out.push("", "### The 50 listed hosts with the fewest labels");
  out.push(shortest.map(plain).join(" ") || "None.");
  out.push("");

  let markdown = out.join("\n");
  if (markdown.length > MAX_REPORT) markdown = `${markdown.slice(0, MAX_REPORT)}\n\n(cut to ${MAX_REPORT} characters)\n`;
  return { markdown, notify };
}
