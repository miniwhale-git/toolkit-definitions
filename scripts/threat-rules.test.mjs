// Tests for the rules that keep ordinary source changes from stopping the lists or warning on good links:
// shorteners and short bare domains, automatic "name used by" listings, the host budget cut and growth hold,
// the build report, the label kinds both sides share, the backup key fixture and the publishing workflow.
// Run with: node --test scripts/*.test.mjs. Nothing here touches the network or a real private key.

import assert from "node:assert/strict";
import { createHash, createPrivateKey, createPublicKey } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, test } from "node:test";
import { fileURLToPath } from "node:url";

import { buildSet, loadVerifiedSet, lookupIn, writeSet } from "./threat-data.mjs";
import { CANARY } from "./threat-sources/canary.mjs";
import { FIXTURE_ENTRIES, fixtureSet } from "./threat-sources/fixture-set.mjs";
import { buildHostTable } from "./threat-sources/host-table.mjs";
import { checkSet, readSet } from "./threat-sources/gates.mjs";
import { IMITATED_NAMES, SCAM_ENDINGS, SERVICE_WORDS, loadKeepList, loadShorteners, parseKeepList, parseShorteners, parseWords, shortNameCheck, shortNameRule, withShorteners } from "./threat-sources/hosts.mjs";
import { loadKeepApps } from "./threat-sources/keep-apps.mjs";
import { GENERIC_KIND_OF, KINDS, LABEL_KIND_OF, labelKind, nameUsedLabel, shownLabel, threatLabel } from "./threat-sources/labels.mjs";
import { LABELS as MVT_LABELS, campaignLabel } from "./threat-sources/mvt.mjs";
import { buildReport, plain } from "./threat-sources/report.mjs";
import { publicKeyFrom, publicKeys, signedByAny } from "./threat-sources/sign.mjs";
import { SOURCE_ROWS, URLS } from "./threat-sources/sources.mjs";
import { registrableOf, suffixOf } from "./threat-sources/suffixes.mjs";
import { cleanLabel, lookupText, openTable } from "./threat-sources/tkl.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FIX = path.join(HERE, "threat-sources", "fixtures");
const fixture = (name) => readFileSync(path.join(FIX, name), "utf8");
const APP = path.join(HERE, "..", "app", "src", "main", "java", "com", "attnom", "folio");
const eq = assert.deepStrictEqual;
const ok = assert.ok;
const failing = (results) => results.filter((r) => !r.ok).map((r) => r.gate);

// The same throwaway key as threat-data.test.mjs: a fixed seed, not a secret.
const SEED = createHash("sha256").update("toolkit threat-data test key, not a secret").digest();
const TEST_PRIVATE = createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), SEED]), format: "der", type: "pkcs8" });
const TEST_PUBLIC = publicKeyFrom(Buffer.from(createPublicKey(TEST_PRIVATE).export({ format: "jwk" }).x, "base64url").toString("base64"));

// ---- a build on the fixtures, with sources a test can change --------------------------------------------------

const STIX = {
  "intellexa_predator/predator.stix2": "stix-predator.json",
  "2022-06-23_rcs_lab/rcs.stix2": "stix-rcs.json",
  "cellebrite/cellebrite.stix2": "stix-cellebrite.json",
  "2024-12-16_serbia_novispy/novispy.stix2": "stix-novispy.json",
};
const ANSWERS = new Map([
  [URLS.echapIoc, fixture("echap-ioc.yaml")],
  [URLS.echapWatchware, fixture("echap-watchware.yaml")],
  [URLS.echapSamples, fixture("echap-samples.csv")],
  [URLS.mvtIndex, fixture("mvt-indicators.yaml")],
  [URLS.phishing, fixture("phishing-domains.txt")],
  [URLS.certPl, fixture("certpl-domains.txt")],
]);
/** The fixtures, with `extra[url]` lines added to that source. */
const sources = (extra = {}) => async (url) => {
  if (ANSWERS.has(url)) return extra[url] ? `${ANSWERS.get(url).trimEnd()}\n${extra[url]}\n` : ANSWERS.get(url);
  const known = Object.entries(STIX).find(([p]) => url.endsWith(p));
  if (known) return fixture(known[1]);
  if (url.endsWith(".stix2")) return JSON.stringify({ type: "bundle", id: "bundle--empty", objects: [] });
  throw new Error(`${url}: not in the fixtures`);
};
const keep = loadKeepList();
const keepApps = loadKeepApps();
const rows = SOURCE_ROWS.map((r) => ({ ...r, min: 1 }));
const run = (extra = {}) =>
  buildSet({ fetchText: sources(), keep, keepApps, now: new Date("2026-03-04T05:06:07Z"), seq: 2, privateKey: TEST_PRIVATE, publicKey: TEST_PUBLIC, requireSignature: true, rows, maxRejected: 0.3, log: () => {}, ...extra });
/** Writes a built set to a temporary folder and reads it back as the previous set of a later build. */
function asPrevious(built) {
  const dir = mkdtempSync(path.join(tmpdir(), "defs-prev-"));
  writeSet(dir, built.set, { publicKey: TEST_PUBLIC, keep });
  return { dir, previous: loadVerifiedSet(dir, TEST_PUBLIC) };
}

// ---- shorteners and short bare domains -----------------------------------------------------------------------

/** The hosts in KnownHosts.SHORTENER_HOSTS, read from the Kotlin file as text. */
function appShorteners() {
  const kt = readFileSync(path.join(APP, "security", "links", "KnownHosts.kt"), "utf8");
  const block = /SHORTENER_HOSTS[^=]*=\s*setOf\(([\s\S]*?)\)/.exec(kt);
  ok(block, "KnownHosts.kt has no SHORTENER_HOSTS = setOf(...)");
  return [...block[1].matchAll(/"([^"]+)"/g)].map((m) => m[1]);
}

describe("shorteners", () => {
  const shorteners = loadShorteners();

  test("the data file is large, valid, and holds the services the review found listed", () => {
    ok(shorteners.length >= 250, `only ${shorteners.length} shorteners`);
    for (const host of ["gg.gg", "x.co", "2.gd", "qr.de", "9qr.de", "qr1.be", "l.ead.me", "bitly.ws", "bit.ly", "linktr.ee", "qrco.de", "t.co"]) ok(shorteners.includes(host), host);
    assert.throws(() => parseShorteners("bit.ly\nbit.ly\n"), /twice/);
    assert.throws(() => parseShorteners("Bit.ly\n"), /not a host/);
    assert.throws(() => parseShorteners("bit.ly shared\n"), /not a host/);
  });

  test("every shortener the app knows (KnownHosts.SHORTENER_HOSTS) is in the data file", { skip: !existsSync(path.join(APP, "security", "links", "KnownHosts.kt")) && "KnownHosts.kt is not in this repository" }, () => {
    const app = appShorteners();
    ok(app.length >= 30, `read only ${app.length} hosts from KnownHosts.kt`);
    const missing = app.filter((h) => !shorteners.includes(h));
    eq(missing, [], `add these to scripts/threat-sources/shorteners.txt: ${missing.join(" ")}`);
  });

  test("each becomes a shared keep-list entry; one kept whole in keep-hosts.txt stays whole", () => {
    for (const host of shorteners) ok(keep.has(host), `${host} is in the keep-list`);
    eq(keep.get("l.ead.me"), true);
    eq(keep.get("bit.ly"), false, "keep-hosts.txt keeps bit.ly whole, which wins");
    const merged = withShorteners(parseKeepList("bit.ly\n"), ["bit.ly", "gg.gg"]);
    eq([...merged], [["bit.ly", false], ["gg.gg", true]]);
  });

  test("a phishing list that names the services lists none of them, and still lists a host below one", async () => {
    const extra = { [URLS.phishing]: ["gg.gg", "x.co", "2.gd", "qr.de", "9qr.de", "qr1.be", "l.ead.me", "bitly.ws", "evil-page.gg.gg", "login-check.l.ead.me"].join("\n") };
    const built = await run({ fetchText: sources(extra) });
    eq(failing(built.results), []);
    const dir = mkdtempSync(path.join(tmpdir(), "defs-short-"));
    writeSet(dir, built.set, { publicKey: TEST_PUBLIC, keep });
    for (const host of ["gg.gg", "x.co", "2.gd", "qr.de", "9qr.de", "qr1.be", "l.ead.me", "ead.me", "bitly.ws"]) eq(lookupIn(dir, "host", host).found, null, `${host} must not be listed`);
    eq(lookupIn(dir, "host", "evil-page.gg.gg").found, "evil-page.gg.gg", "a deeper host on a shortener stays listed");
    eq(lookupIn(dir, "host", "login-check.l.ead.me").found, "login-check.l.ead.me");
    rmSync(dir, { recursive: true, force: true });
  });
});

describe("short bare domains", () => {
  test("suffixes: a country's second level, a common registry word, and nothing private", () => {
    eq([suffixOf("a.sbi.co.in"), registrableOf("a.sbi.co.in")], ["co.in", "sbi.co.in"]);
    eq([suffixOf("evil.net"), registrableOf("evil.net")], ["net", "evil.net"]);
    eq(registrableOf("abc.com.xx"), "abc.com.xx", "a common registry word under an unknown country");
    eq(registrableOf("abc.blogspot.com"), "blogspot.com", "a page on shared hosting is a deeper name");
    eq([registrableOf("co.uk"), registrableOf("1.2.3.4")], [null, null]);
  });

  test("the rule: four letters or fewer, or six or fewer when one source alone lists it, bare names only", () => {
    // gg.gg and abcd.co.uk were checked with two or three sources; a second source now keeps a short name
    // (finding 1), so the length rule is checked with one. gg.gg stays out through shorteners.txt.
    eq(shortNameRule("gg.gg", 1), "short");
    eq(shortNameRule("qr1.be", 1), "short");
    eq(shortNameRule("abcd.co.uk", 1), "short");
    eq(shortNameRule("bitly.ws", 1), "one source");
    eq(shortNameRule("bitly.ws", 2), null, "two sources list it");
    eq(shortNameRule("abcdef.com", 1), "one source");
    eq(shortNameRule("abcdefg.com", 1), null);
    eq(shortNameRule("evil.gg.gg", 1), null, "a deeper host stays");
    eq(shortNameRule("203.0.113.9", 1), null, "an address is not a name");
  });

  test("a brand-built name, a scam ending or a second source keeps a short name (finding 1)", () => {
    // The four DHL names the previous set had and this rule dropped, each listed by one source.
    for (const host of ["dhl1.net", "dhl2.help", "dhlapp.top", "dhlpay.shop"]) {
      eq(shortNameRule(host, 1), null, host);
      eq(shortNameCheck(host, 1).exception, "brand", host);
    }
    eq(shortNameCheck("sbi1.in", 1), { rule: "short", exception: "brand" }, "digits before or after");
    eq(shortNameCheck("upspay.de", 1), { rule: "one source", exception: "brand" }, "a service word");
    // Any other addition is not built the scam way: DHL Group's own site, and ordinary names (review, finding 7).
    for (const host of ["xsbi.in", "upsx.de", "dpdhl.com", "groups.io", "cups.org"]) eq(shortNameCheck(host, 1).exception, null, host);
    // Hyphens are read through, and the end is tried when the start does not fit (second review, finding 9).
    eq(shortNameCheck("sbi-1.in", 1).exception, "brand");
    eq(shortNameCheck("appdhl.com", 1).exception, "brand");
    eq(shortNameCheck("qr9.top", 1), { rule: "short", exception: "scam ending" });
    eq(shortNameCheck("abcdef.help", 1), { rule: "one source", exception: "scam ending" });
    eq(shortNameCheck("qr9.de", 2), { rule: "short", exception: "two sources" });
    eq(shortNameCheck("abcdefg.com", 1), { rule: null, exception: null }, "long enough: no rule, so no exception");
    // The brand's bare name on another ending is most often its own site: still dropped.
    eq(shortNameRule("dhl.de", 1), "short");
    eq(shortNameRule("paypal.de", 1), "one source");
    // Below a shortener nothing changes; the shortener itself never reaches this rule (keep-list).
    eq(shortNameRule("dhl1.gg.gg", 1), null);
  });

  test("the writer's copies of the app's names and endings equal the Kotlin sets", { skip: !existsSync(path.join(APP, "security", "links", "KnownHosts.kt")) && "KnownHosts.kt is not in this repository" }, () => {
    const kt = readFileSync(path.join(APP, "security", "links", "KnownHosts.kt"), "utf8");
    const set = (name) => {
      const block = new RegExp(`${name}[^=]*=\\s*setOf\\(([\\s\\S]*?)\\)`).exec(kt);
      ok(block, `KnownHosts.kt has no ${name} = setOf(...)`);
      return [...block[1].matchAll(/"([^"]+)"/g)].map((m) => m[1]).sort();
    };
    const imitated = set("COMMONLY_IMITATED");
    const endings = set("SCAM_FAVOURED_ENDINGS");
    ok(imitated.length >= 50 && endings.length >= 30, `read ${imitated.length} names and ${endings.length} endings`);
    eq([...IMITATED_NAMES].sort(), imitated, "run the export again: scripts/threat-sources/imitated-names.txt differs from KnownHosts.COMMONLY_IMITATED");
    eq([...SCAM_ENDINGS].sort(), endings, "scripts/threat-sources/scam-endings.txt differs from KnownHosts.SCAM_FAVOURED_ENDINGS");
    const built = readFileSync(path.join(APP, "security", "links", "BuiltNames.kt"), "utf8");
    const words = ["ALARM_WORDS", "PLAIN_WORDS"].flatMap((name) => {
      const block = new RegExp(`val ${name}[^=]*=\\s*setOf\\(([\\s\\S]*?)\\)`).exec(built);
      ok(block, `BuiltNames.kt has no ${name} = setOf(...)`);
      return [...block[1].matchAll(/"([^"]+)"/g)].map((m) => m[1]);
    });
    ok(words.length >= 30, `read ${words.length} service words`);
    eq([...SERVICE_WORDS].sort(), words.sort(), "hosts.mjs SERVICE_WORDS differs from BuiltNames.ALARM_WORDS + PLAIN_WORDS");
    assert.throws(() => parseWords("dhl\ndhl\n", "x"), /twice/);
    assert.throws(() => parseWords("DHL\n", "x"), /lower-case/);
  });

  test("it runs on the bulk lists only, counts each rule, and the curated spyware lists keep their short domains", () => {
    const part = (id, hosts) => ({ id, pkg: [], cert: [], sha: [], hosts, rejected: 0, raw: hosts.length, notes: [] });
    const table = buildHostTable([part("mvt", ["tly.link", "bity.ws"]), part("phishing", ["qr9.de", "abcde.de", "abcdef.net", "abcdefg.com", "deep.qr9.de"]), part("certpl", ["abcdef.net"])], { keep: new Map(), cap: 100 });
    eq(table.hosts.sort(), ["abcdef.net", "abcdefg.com", "bity.ws", "deep.qr9.de", "tly.link"]);
    eq(table.short, [{ id: "phishing", rule: "short", host: "qr9.de" }, { id: "phishing", rule: "one source", host: "abcde.de" }]);
    ok(table.lines.some((l) => l.startsWith("hosts phishing:") && l.includes("2 short bare domains dropped")));
  });

  test("the build names how many each rule dropped, with examples", async () => {
    const built = await run({ fetchText: sources({ [URLS.phishing]: "qr7.de\nabcde.de", [URLS.certPl]: "zz9.pl" }) });
    const gate = built.results.find((r) => r.gate === "short names");
    ok(gate.ok && /^3 short bare domains dropped \(short certpl 1, short phishing 1, one source phishing 1\), e\.g\. zz9\.pl, qr7\.de, abcde\.de; kept by an exception: brand 0, scam ending 0, two sources 0$/.test(gate.detail), gate.detail);
    ok(/qr7\.de/.test(gate.detail) && /Short bare domains dropped: 3/.test(built.report.markdown));
  });

  test("the build lists the DHL names again and counts each exception", async () => {
    const extra = { [URLS.phishing]: "dhl1.net\ndhl2.help\ndhlapp.top\ndhlpay.shop\nqr8.top\nqr7.de\nzz8.pl", [URLS.certPl]: "zz8.pl" };
    const built = await run({ fetchText: sources(extra) });
    eq(failing(built.results), []);
    const gate = built.results.find((r) => r.gate === "short names");
    ok(/kept by an exception: brand 4, scam ending 1, two sources 2, e\.g\. /.test(gate.detail), gate.detail);
    ok(/Short bare domains kept by an exception: 7; brand 4, scam ending 1, two sources 2\./.test(built.report.markdown), built.report.markdown);
    for (const host of ["dhl1.net", "dhl2.help", "dhlapp.top", "dhlpay.shop", "qr8.top", "zz8.pl"]) ok(built.hosts.includes(host), host);
    ok(!built.hosts.includes("qr7.de"));
  });
});

// ---- packages under a system prefix --------------------------------------------------------------------------

describe("system prefixes", () => {
  const withEchapApp = (yaml) => async (url) => (url === URLS.echapIoc ? `${fixture("echap-ioc.yaml").trimEnd()}\n${yaml}` : sources()(url));
  const sneaky = "- name: Sneaky\n  type: stalkerware\n  packages:\n  - com.android.sneaky.one\n  - com.android.sneaky.two\n  - com.google.android.sneaky\n  - android.sneaky.four\n  - com.android.sneaky.five\n";

  test("a new upstream name under a prefix is listed as 'name used by', printed, and never counts toward the gate", async () => {
    const lines = [];
    const built = await run({ fetchText: withEchapApp(sneaky), log: (l) => lines.push(l) });
    eq(failing(built.results), [], "five names under the prefixes do not stop the build");
    ok(/0 distinct entries dropped, 0 new/.test(built.results.find((r) => r.gate === "app keep-lists").detail));
    const pkg = openTable(built.set.files.get("apps-pkg.tkl"), "apps-pkg.tkl");
    for (const name of ["com.android.sneaky.one", "com.google.android.sneaky", "android.sneaky.four"]) eq(lookupText(pkg, name), "Sneaky (name used by stalkerware)", name);
    ok(lines.includes('listed automatically: package com.android.sneaky.one as "Sneaky (name used by stalkerware)" (from echap; under com.android.*)'), lines.filter((l) => l.includes("automatically")).join("\n"));
    ok(built.report.markdown.includes("- com.android.sneaky.two as Sneaky (name used by stalkerware) (from echap)"));
  });

  test("against a previous set, a new automatic listing asks for a look; the reviewed ones do not", async () => {
    const { dir, previous } = asPrevious(await run());
    const plainRun = await run({ previous, seq: 3 });
    eq(plainRun.report.notify, [], plainRun.report.notify.join());
    const sneakyRun = await run({ previous, seq: 3, fetchText: withEchapApp(sneaky) });
    ok(sneakyRun.report.notify.includes("5 new packages listed under a system prefix"), sneakyRun.report.notify.join());
    ok(sneakyRun.report.markdown.includes("com.android.sneaky.five as Sneaky (name used by stalkerware) (from echap), NEW since the previous set"));
    rmSync(dir, { recursive: true, force: true });
  });

  test("exact keep-list hits still count, and four new ones still fail the build", async () => {
    const four = "- name: Tampered\n  type: stalkerware\n  packages:\n  - com.whatsapp\n  - com.android.vending\n  - com.google.android.gms\n  - com.android.systemui\n";
    const built = await run({ fetchText: withEchapApp(four) });
    eq(failing(built.results), ["app keep-lists"]);
    ok(/4 new \(at most 3\)/.test(built.results.find((r) => r.gate === "app keep-lists").detail));
    ok(built.report.notify.includes("4 new keep-list hits dropped") && built.report.markdown.startsWith("<!-- notify: yes -->"));
    eq(lookupText(openTable(built.set.files.get("apps-pkg.tkl"), "p"), "com.android.vending"), null);
  });
});

// ---- host growth -----------------------------------------------------------------------------------------------

describe("host growth", () => {
  const grown = (n) => Array.from({ length: n }, (_, i) => `grown-host-${String(i).padStart(4, "0")}.example`).join("\n");

  test("a host source that more than doubles is held at its previous data, reported, and the rest is published", async () => {
    const { dir, previous } = asPrevious(await run());
    const before = previous.manifest.sources.find((s) => s.name === rows.find((r) => r.id === "phishing").name).entries;
    const built = await run({ previous, seq: 3, fetchText: sources({ [URLS.phishing]: grown(before + 5) }) });
    eq(failing(built.results), [], "a hold never stops the build");
    const gate = built.results.find((r) => r.gate === "host growth");
    ok(new RegExp(`phishing ${before} -> ${2 * before + 5} entries: HELD at its previous data, ${before} hosts kept\\. If the source really grew, run the workflow with allow_growth`).test(gate.detail), gate.detail);
    const hosts = openTable(built.set.files.get("hosts.tkl"), "hosts");
    eq(lookupText(hosts, "grown-host-0001.example"), null, "nothing new from the held source");
    eq(lookupText(hosts, "00000000000000000000000000000000000000000.xyz") !== null, true, "its previous hosts stay");
    ok(built.report.notify.includes("phishing held at the previous data"));
    eq(built.manifest.sources.find((s) => s.name === rows.find((r) => r.id === "phishing").name).entries, before, "the manifest counts what was kept");

    const allowed = await run({ previous, seq: 3, allowGrowth: true, fetchText: sources({ [URLS.phishing]: grown(before + 5) }) });
    eq(lookupText(openTable(allowed.set.files.get("hosts.tkl"), "hosts"), "grown-host-0001.example") !== null, true, "allow_growth publishes it");
    ok(/allowed by --allow-growth/.test(allowed.results.find((r) => r.gate === "host growth").detail));
    const doubled = await run({ previous, seq: 3, fetchText: sources({ [URLS.phishing]: grown(before) }) });
    eq(doubled.results.find((r) => r.gate === "host growth").detail, "no host source more than doubled since the previous set", "exactly double is not more than double");
    rmSync(dir, { recursive: true, force: true });
  });

  test("the failure texts name the override inputs", async () => {
    const { dir, previous } = asPrevious(await run());
    const halved = async (url) => (url === URLS.phishing || url === URLS.certPl ? fixture("phishing-domains.txt").split("\n").slice(0, 8).join("\n") : sources()(url));
    const dropped = await run({ previous, seq: 4, fetchText: halved });
    ok(/run the workflow with allow_drop \(--allow-drop\)/.test(dropped.results.find((r) => r.gate === "drop").detail));
    const withMany = async (url) => (url === URLS.echapIoc ? `${fixture("echap-ioc.yaml").trimEnd()}\n- name: Many\n  type: stalkerware\n  packages:\n${Array.from({ length: 400 }, (_, i) => `  - com.many.app${i}`).join("\n")}\n` : sources()(url));
    const grew = await run({ previous, seq: 4, fetchText: withMany });
    ok(/run the workflow with allow_growth \(--allow-growth\)/.test(grew.results.find((r) => r.gate === "growth").detail), grew.results.find((r) => r.gate === "growth").detail);
    rmSync(dir, { recursive: true, force: true });
  });
});

// ---- the report ----------------------------------------------------------------------------------------------------

describe("report", () => {
  const base = { version: 2026111301, ok: true, results: [{ gate: "x", ok: true, detail: "fine" }], appDrops: [], newCerts: new Map(), autoListed: [], previousPkg: null, budget: { trims: [] }, held: [], short: [], shortest: ["a.example"] };

  test("a quiet run asks for nothing; each reason to look is named", () => {
    eq(buildReport(base).notify, []);
    ok(buildReport(base).markdown.startsWith("<!-- notify: no -->\n## Daily lists: v2026111301 built"));
    const known = { table: "cert", text: "61ed377e85d386a8dfee6b864bd85b0bfaa5af81", label: "X (stalkerware)", source: "echap", rule: "keep 61ed", known: true };
    eq(buildReport({ ...base, appDrops: [known, known] }).notify, [], "a known hit is expected every day");
    eq(buildReport({ ...base, appDrops: [{ ...known, table: "pkg", text: "com.whatsapp", known: false }] }).notify, ["1 new keep-list hits dropped"]);
    eq(buildReport({ ...base, newCerts: new Map([["ab".repeat(20), "New (stalkerware)"]]) }).notify, ["1 new certificate entries"]);
    eq(buildReport({ ...base, budget: { trims: [{ id: "phishing", wanted: 9, cut: 2 }] } }).notify, ["hosts trimmed to fit the budget"]);
    eq(buildReport({ ...base, ok: false }).notify, ["a gate failed, nothing was published"]);
    eq(buildReport({ ...base, newCerts: null }).notify, [], "no previous set: nothing to compare");
  });

  test("text from a source cannot break the page or mention anyone", () => {
    eq(plain("a`b@c\nd"), "abc d");
    const md = buildReport({ ...base, results: [{ gate: "source", ok: false, detail: "line 3: \"```@everyone\"" }], autoListed: [{ text: "com.android.x", label: "`@team (name used by stalkerware)", source: "echap", rule: "r" }] }).markdown;
    ok(!md.includes("`") && !md.includes("@"), md);
  });
});

// ---- label kinds: the writer's side of the parity test ----------------------------------------------------------

/** Every label the writer can make, and some a tampered list could hold, with what the app shows and its kind. */
function labelCases() {
  const cases = new Map();
  const add = (label, from) => {
    const clean = cleanLabel(label);
    if (!cases.has(label)) cases.set(label, { label, from, shown: shownLabel(clean), kind: labelKind(clean) });
  };
  const good = ["mSpy", "Wise Mo_2.0-x", "a1234", "Spy.Ware", "x".repeat(30)];
  const bad = ["Call +1 555 0100", "Call 5550100 now", "visit www.example", "HTTPie", "x".repeat(31), "12345", "...", "Spуware", "Spy (pro)", "help@remove.it"];
  for (const kind of Object.keys(KINDS)) {
    for (const name of good) add(threatLabel(name, kind), `writer: name passes, ${kind}`);
    for (const name of bad) add(threatLabel(name, kind), `writer: name fails, ${kind}`);
    add(nameUsedLabel(threatLabel("Snoopza", kind)), `writer: under a system prefix, ${kind}`);
    add(nameUsedLabel(KINDS[kind]), `writer: under a system prefix, plain ${kind}`);
  }
  for (const label of Object.values(MVT_LABELS)) add(label, "writer: MVT campaign");
  add(campaignLabel("Some_Campaign"), "writer: MVT campaign");
  add(campaignLabel("Call_+1_555_0100"), "writer: MVT campaign, name fails");
  add(CANARY.label, "writer: canary");
  for (const raw of [
    "Call +1 555 0100 (stalkerware)", "12345 (watchware)", "www (spyware)", "HTTP spy (name used by watchware)", `${"x".repeat(31)} (forensic tool)`,
    "mSpy (malware)", "mSpy (stalkerware) ", " mSpy (stalkerware)", "a (stalkerware) (spyware)", "Spуware (stalkerware)", "mSpy‮ (stalkerware)",
    "Listed app", "mSpy", "Monitoring app (stalkerware)",
  ]) add(raw, "outside: as a tampered list could hold it");
  return [...cases.values()];
}

describe("label kinds", () => {
  const file = path.join(FIX, "label-kinds.json");

  test("fixtures/label-kinds.json holds every kind and plain word the writer makes, as the writer reads them", () => {
    const cases = labelCases();
    const text = `${JSON.stringify({ note: "Labels the writer can make (and some from outside), what the app shows for each (LabelText.shown of LabelText.clean) and its kind (LabelText.kindOf). Written by scripts/threat-rules.test.mjs; LabelKindTest reads it.", cases }, null, 2)}\n`;
    if (existsSync(file)) eq(readFileSync(file, "utf8"), text, "label-kinds.json differs from what the writer makes now; delete it to regenerate");
    else writeFileSync(file, text);
    const kinds = new Set(cases.map((c) => c.kind));
    for (const kind of [...Object.values(LABEL_KIND_OF), ...Object.values(GENERIC_KIND_OF), "UNKNOWN"]) ok(kinds.has(kind), `no case of ${kind}`);
    ok(cases.length >= 50, `${cases.length} cases`);
    ok(cases.filter((c) => c.from.startsWith("writer")).every((c) => c.kind !== "UNKNOWN" || c.label === CANARY.label), "every writer label but the canary has a kind");
  });

  test("the writer's kind rule follows its own label rule", () => {
    eq(labelKind("mSpy (stalkerware)"), "STALKERWARE");
    eq(labelKind("Stalkerware"), "GENERIC_THREAT");
    eq(labelKind("Name used by a monitoring app"), "GENERIC_MONITORING");
    eq(labelKind("Call 5550100 (watchware)"), "GENERIC_MONITORING", "a name with five digits in a row shows as the plain word");
    eq(labelKind("Mercenary campaign (spyware)"), "SPYWARE");
    eq(labelKind("mSpy (malware)"), "UNKNOWN");
  });
});

// ---- the backup key ----------------------------------------------------------------------------------------------

describe("backup key", () => {
  const dir = path.join(FIX, "backup-key-set");

  test("fixtures/backup-key-set is the fixed tiny set, signed by the second production key and only by it", () => {
    ok(existsSync(path.join(dir, "manifest.json.sig")), "fixtures/backup-key-set is missing: sign it once with the offline key (threat-data.mjs sign-fixture)");
    const set = readSet(dir);
    const expected = fixtureSet();
    eq(set.manifestBytes.equals(expected.manifestBytes), true, "the manifest is the fixed one");
    for (const [name, bytes] of expected.files) eq(set.files.get(name)?.equals(bytes), true, name);
    const keys = publicKeys();
    eq(signedByAny(set.manifestBytes, set.signature, keys), 1, "valid for the backup key");
    eq(signedByAny(set.manifestBytes, set.signature, [keys[0]]), -1, "not for the daily key");
    eq(failing(checkSet(set, { publicKey: keys, keep, requireSignature: true })), []);
    eq(lookupIn(dir, "package", FIXTURE_ENTRIES.pkg[0].text).found, FIXTURE_ENTRIES.pkg[0].label);
    eq(lookupIn(dir, "host", `a.${FIXTURE_ENTRIES.hosts[0]}`).found, FIXTURE_ENTRIES.hosts[0]);
  });
});

// ---- the publishing workflow -------------------------------------------------------------------------------------

const WORKFLOW = [path.join(HERE, "..", ".github", "workflows", "publish-lists.yml"), path.join(HERE, "..", "definitions-site", ".github", "workflows", "publish-lists.yml")].find(existsSync);

describe("publishing workflow", { skip: !WORKFLOW && "no publish-lists.yml in this repository" }, () => {
  const yml = WORKFLOW ? readFileSync(WORKFLOW, "utf8") : "";
  const job = (name) => {
    const start = yml.indexOf(`\n  ${name}:\n`);
    ok(start >= 0, `no job ${name}`);
    const next = yml.slice(start + 1).search(/\n {2}[a-z][a-z-]*:\n/);
    return next < 0 ? yml.slice(start) : yml.slice(start, start + 1 + next);
  };

  test("a first job outside the publish environment fails when the key is a repository secret", () => {
    const guard = job("key-guard");
    ok(!/environment:/.test(guard), "key-guard must not use an environment");
    ok(guard.includes("${{ secrets.TOOLKIT_DEFS_KEY != '' }}"), guard);
    ok(/exit 1/.test(guard));
    ok(/needs: key-guard/.test(job("build")), "build waits for key-guard");
  });

  test("multi-line outputs use a random delimiter; issue text loses backticks and @", () => {
    ok(!/<<END_OF_REPORT/.test(yml) && !/<<EOF\b/.test(yml), "a fixed heredoc delimiter");
    ok(/delimiter="[^"\n]*\$\((openssl rand|head -c)/.test(yml), "a random delimiter");
    ok(yml.includes("tr -d '`@'"), "backticks and @ stripped");
  });

  test("the report reaches the run summary and the one 'Daily lists' issue, also on runs that pass", () => {
    ok(yml.includes("GITHUB_STEP_SUMMARY"));
    ok(yml.includes("--report report.md"));
    ok(yml.includes('title="Daily lists"') && !yml.includes('title="Daily lists failed"'));
    ok(job("report").includes("if: ${{ always() && (needs.build.result == 'failure' || needs.build.outputs.notify == 'yes' || needs.key-guard.result == 'failure') }}"), "report job condition");
    ok(/gh issue edit "\$number" [^\n]*--body-file/.test(job("report")), "the body gets the latest report");
    ok(/allow_drop:/.test(yml) && /allow_growth:/.test(yml));
    ok(yml.includes("node --test scripts/*.test.mjs"), "every test file runs");
  });
});
