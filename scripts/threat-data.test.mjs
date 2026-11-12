// Tests for scripts/threat-data.mjs and scripts/threat-sources/. Run with: node --test scripts/*.test.mjs
// Nothing here touches the network or a real key: sources are fixtures cut from the real files
// (scripts/threat-sources/fixtures), downloads are faked, and the signing key is a throwaway one
// made from a fixed seed, so the signed fixture set written to fixtures/tiny-set is the same on
// every run. The last line printed says how many checks ran.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { X509Certificate, createHash, createPrivateKey, createPublicKey, generateKeyPairSync } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, test } from "node:test";
import { fileURLToPath } from "node:url";

import { OlderFormat, PUBLISHED_BASE, buildDate, buildSet, fetchPublished, loadVerifiedSet, lookupIn, parseCommandLine, siteCopies, writeSet } from "./threat-data.mjs";
import { NO_KEEP_APPS, assemble, maxHostEntries, shortestHosts } from "./threat-sources/assemble.mjs";
import { echapItems, parseEchapYaml, parseSamplesCsv } from "./threat-sources/echap.mjs";
import { makeFetcher } from "./threat-sources/fetch.mjs";
import { appKeepGate, checkSet, hostBudgetGate, hostListed, keepRescan, newCertificateLines, previousGates, readSet, sourceGates } from "./threat-sources/gates.mjs";
import { applyKeepList, buildKeeper, hostWalk, loadKeepList, normaliseHost, parseKeepList } from "./threat-sources/hosts.mjs";
import { MAX_NEW_HITS, certRule, loadKeepApps, loadKeepCerts, loadKeepPackages, packageRule, parseKeepCerts, parseKeepPackages } from "./threat-sources/keep-apps.mjs";
import { KINDS, NAME_MAX, labelAllowed, nameUsedLabel, safeName, threatLabel } from "./threat-sources/labels.mjs";
import { FILES, LIMITS, datedAhead, manifestBytes, parseManifest, versionFor } from "./threat-sources/manifest.mjs";
import { LABELS as MVT_LABELS, campaignLabel, parseIndex, parseStix } from "./threat-sources/mvt.mjs";
import { PUBLIC_KEY, PUBLIC_KEYS, privateKeyFromEnv, publicKeyFrom, publicKeys, signBytes, signatureValid, signedByAny } from "./threat-sources/sign.mjs";
import { SOURCE_ROWS, URLS } from "./threat-sources/sources.mjs";
import { cleanLabel, keyOf, lookupText, openTable, sha256Hex, tableProblems, writeTable } from "./threat-sources/tkl.mjs";
import { YamlError, parseYaml } from "./threat-sources/yaml.mjs";
import { CANARY, withCanary } from "./threat-sources/canary.mjs";
import { readHost } from "./threat-sources/hosts.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FIX = path.join(HERE, "threat-sources", "fixtures");
const fixture = (name) => readFileSync(path.join(FIX, name), "utf8");

// ---- counting checks -------------------------------------------------------------------------------------------

let checks = 0;
const eq = (actual, expected, message) => {
  checks++;
  assert.deepStrictEqual(actual, expected, message);
};
const ok = (value, message) => {
  checks++;
  assert.ok(value, message);
};
const fails = (fn, pattern, message) => {
  checks++;
  assert.throws(fn, pattern, message);
};

// ---- a throwaway key from a fixed seed (the same signature on every run) -----------------------------------

const SEED = createHash("sha256").update("toolkit threat-data test key, not a secret").digest();
const TEST_PRIVATE = createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), SEED]), format: "der", type: "pkcs8" });
const TEST_PUBLIC_B64 = Buffer.from(createPublicKey(TEST_PRIVATE).export({ format: "jwk" }).x, "base64url").toString("base64");
const TEST_PUBLIC = publicKeyFrom(TEST_PUBLIC_B64);
const OTHER_PRIVATE = generateKeyPairSync("ed25519").privateKey;

// ---- small sets built in memory --------------------------------------------------------------------------------

const BUILT = new Date("2026-01-01T00:00:00Z");
const TINY = {
  pkg: [
    { text: "com.alpha.spy", label: "Alpha (stalkerware)" },
    { text: "com.beta.watch", label: "Beta (watchware)" },
    { text: "com.gamma.rat", label: "Alpha (stalkerware)" },
  ],
  cert: [
    { text: "0123456789abcdef".repeat(4), label: "Delta (spyware)" },
    { text: "89abcdef01".repeat(4), label: "Zeta (stalkerware)" },
  ],
  sha: [{ text: sha256Hex("tiny apk"), label: "Epsilon (spyware)" }],
  hosts: ["evil.example", "xn--bcher-kva.example", "bad.test", "203.0.113.9", "xn--fa-hia.example"],
};

/** A signed set from table contents, each table with its canary unless `canaries` is false. `mutate(files)` can damage a file after the manifest was made. */
function makeSet({ pkg = TINY.pkg, cert = TINY.cert, sha = TINY.sha, hosts = TINY.hosts, version = 2026010101, builtAt = BUILT, key = TEST_PRIVATE, canaries = true, mutate } = {}) {
  const add = (kind, entries) => (canaries ? withCanary(kind, entries) : entries);
  const built = {
    "apps-pkg.tkl": writeTable({ keyBytes: 8, labelled: true, entries: add("pkg", pkg) }),
    "apps-cert.tkl": writeTable({ keyBytes: 8, labelled: true, entries: add("cert", cert) }),
    "apps-sha.tkl": writeTable({ keyBytes: 8, labelled: true, entries: add("sha", sha) }),
    "hosts.tkl": writeTable({ labelled: false, entries: add("hosts", hosts.map((text) => ({ text }))) }),
  };
  const files = Object.entries(built).map(([name, t]) => ({ name, bytes: t.bytes, entries: t.entries }));
  const bytes = manifestBytes({ version, built: builtAt, files, sources: [{ name: "Test fixture", licence: "CC0-1.0", url: "https://example.invalid/", entries: 8 }] });
  const set = { manifestBytes: bytes, signature: key ? signBytes(bytes, key) : null, files: new Map(files.map((f) => [f.name, f.bytes])) };
  mutate?.(set);
  return set;
}
const options = (extra = {}) => ({ publicKey: TEST_PUBLIC, keep: new Map(), requireSignature: true, ...extra });
const failing = (results) => results.filter((r) => !r.ok).map((r) => r.gate);

// ---- the table writer ---------------------------------------------------------------------------------------------

describe("table writer", () => {
  // Expected bytes made by an independent Python program following DefsFormat.kt (hashlib, struct).
  const PKG_HEX = "544b4c31080200000000000300000002" + "44ced7f23c9adff30000" + "b2e89757a55c387d0000" + "c6b8a3b8eb31bfc10001" + "13416c70686120287374616c6b657277617265291042657461202877617463687761726529";
  const HOSTS_HEX = "544b4c3108000000" + "0000000300000000" + "970ca6b73eaf2630" + "9c180de0cd699ee7" + "b4e22234a9113e1b";

  test("matches hand-computed bytes", () => {
    eq(writeTable({ keyBytes: 8, labelled: true, entries: TINY.pkg }).bytes.toString("hex"), PKG_HEX);
    eq(writeTable({ labelled: false, entries: ["evil.example", "xn--bcher-kva.example", "bad.test"].map((text) => ({ text })) }).bytes.toString("hex"), HOSTS_HEX);
  });

  test("keys are the first 8 bytes of SHA-256 of the UTF-8 text, hosts included", () => {
    eq(keyOf("com.alpha.spy", 8).toString("hex"), "b2e89757a55c387d");
    eq(keyOf("bad.test").toString("hex"), "b4e22234a9113e1b");
    eq(keyOf("xn--bcher-kva.example").toString("hex"), "970ca6b73eaf2630");
  });

  test("a table with 6-byte keys is neither written nor read", () => {
    fails(() => writeTable({ keyBytes: 6, labelled: false, entries: [{ text: "a.b" }] }), /keyBytes must be 8/);
    // Built by hand: the first format's host table, header then one 6-byte key.
    const six = Buffer.concat([Buffer.from("TKL1", "latin1"), Buffer.from([6, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0]), keyOf("bad.test").subarray(0, 6)]);
    fails(() => openTable(six, "hosts.tkl"), /keyBytes is 6, expected 8/);
  });

  test("entries are ordered as unsigned bytes", () => {
    const texts = Array.from({ length: 300 }, (_, i) => `host${i}.example`);
    const table = openTable(writeTable({ labelled: false, entries: texts.map((text) => ({ text })) }).bytes, "t");
    const keys = Array.from({ length: table.entryCount }, (_, i) => Buffer.from(table.bytes.subarray(16 + i * 8, 24 + i * 8)));
    eq(keys.every((k, i) => i === 0 || Buffer.compare(keys[i - 1], k) < 0), true);
    // A signed comparison would put keys starting 0x80 and up first; prove the data has both kinds.
    ok(keys.some((k) => k[0] >= 0x80) && keys.some((k) => k[0] < 0x80), "keys on both sides of 0x80");
    ok(keys[0][0] < 0x80 && keys[keys.length - 1][0] >= 0x80, "low keys first, high keys last");
    eq(tableProblems(table), []);
  });

  test("the same input gives the same bytes; a repeated text is one entry", () => {
    const a = writeTable({ keyBytes: 8, labelled: true, entries: [...TINY.pkg, ...TINY.pkg] });
    eq(a.entries, 3);
    eq(a.bytes.equals(writeTable({ keyBytes: 8, labelled: true, entries: [...TINY.pkg].reverse() }).bytes), true);
    eq(a.labels, ["Alpha (stalkerware)", "Beta (watchware)"]);
  });

  test("an empty table can be written but is refused on reading, as the app refuses it", () => {
    const bytes = writeTable({ keyBytes: 8, labelled: true, entries: [] }).bytes;
    eq([bytes[5], bytes.readUInt32BE(8), bytes.readUInt32BE(12)], [2, 0, 0]);
    fails(() => openTable(bytes, "e"), /no entries/);
  });

  test("labels are cleaned by the app's rules: controls, direction overrides, private use, spacing, length", () => {
    eq(cleanLabel("  Name\u202E (spy)\n\tware \u200B"), "Name (spy) ware");
    eq(cleanLabel("a\u0001b\u00A0\u2028c\uE000d"), "ab cd", "controls and private use dropped, odd spaces made one");
    eq(cleanLabel("x".repeat(100)).length, 60);
    eq(cleanLabel(`${"x".repeat(59)}\u{1F600}`), "x".repeat(59), "a pair is never split at the cut");
    eq(cleanLabel("\u0000\u200B"), "");
    eq(cleanLabel("\ud800"), "", "a lone surrogate is dropped");
    fails(() => writeTable({ keyBytes: 8, labelled: true, entries: [{ text: "a.b", label: "" }] }), /label/);
    fails(() => writeTable({ keyBytes: 7, labelled: true, entries: [] }), /keyBytes/);
    fails(() => writeTable({ keyBytes: 8, labelled: true, entries: [{ text: "a.b" }] }), /labels on every entry/);
  });

  test("the same text twice is one entry and not counted as a collision", () => {
    const t = writeTable({ labelled: false, entries: [{ text: "same.test" }, { text: "same.test" }] });
    eq([t.entries, t.collisions], [1, 0]);
  });
});

describe("table reader", () => {
  const good = writeTable({ keyBytes: 8, labelled: true, entries: TINY.pkg }).bytes;
  const mutated = (fn) => {
    const b = Buffer.from(good);
    fn(b);
    return b;
  };

  test("finds every entry and misses the rest", () => {
    const t = openTable(good, "apps-pkg");
    eq(lookupText(t, "com.alpha.spy"), "Alpha (stalkerware)");
    eq(lookupText(t, "com.beta.watch"), "Beta (watchware)");
    eq(lookupText(t, "com.gamma.rat"), "Alpha (stalkerware)");
    eq(lookupText(t, "com.alpha.Spy"), null);
    eq(lookupText(t, ""), null);
  });

  test("refuses a file that is not laid out as the format says", () => {
    fails(() => openTable(Buffer.alloc(8), "t"), /header/);
    fails(() => openTable(mutated((b) => b.write("TKL2", 0, "latin1")), "t"), /TKL1/);
    fails(() => openTable(mutated((b) => (b[4] = 7)), "t"), /keyBytes/);
    fails(() => openTable(mutated((b) => (b[4] = 6)), "t"), /keyBytes is 6, expected 8/);
    fails(() => openTable(mutated((b) => (b[5] = 1)), "t"), /valueBytes/);
    fails(() => openTable(mutated((b) => (b[7] = 1)), "t"), /reserved/);
    fails(() => openTable(mutated((b) => b.writeUInt32BE(1000, 8)), "t"), /do not fit/);
    fails(() => openTable(Buffer.concat([good, Buffer.from([0])]), "t"), /stray/);
    fails(() => openTable(good.subarray(0, good.length - 3), "t"), /label/);
    fails(() => openTable(mutated((b) => b.writeUInt32BE(5, 12)), "t"), /label/);
    const labelsAt = 16 + 3 * 10;
    fails(() => openTable(mutated((b) => (b[labelsAt + 1] = 0xff)), "t"), /not valid UTF-8/);
    fails(() => openTable(mutated((b) => b.fill(0x01, labelsAt + 1, labelsAt + 1 + b[labelsAt])), "t"), /no visible text/);
    const noLabels = Buffer.from(good.subarray(0, labelsAt));
    noLabels.writeUInt32BE(0, 12);
    fails(() => openTable(noLabels, "t"), /values but no labels/);
  });
});

// ---- host names ------------------------------------------------------------------------------------------------------

describe("host names", () => {
  const cases = [
    ["Example.COM", "example.com"],
    ["example.com.", "example.com"],
    ["  www.Example.com  ", "www.example.com"],
    ["Bücher.example", "xn--bcher-kva.example"],
    ["MÜNCHEN.de", "xn--mnchen-3ya.de"],
    ["例え.jp", "xn--r8jz45g.jp"],
    ["xn--bcher-kva.example", "xn--bcher-kva.example"],
    ["a_b.example.com", "a_b.example.com"],
    ["x-y.example.co.in", "x-y.example.co.in"],
    ["1.2.3.4", "1.2.3.4"],
    ["203.0.113.9", "203.0.113.9"],
    ["10.0.0.1", null],
    ["127.0.0.1", null],
    ["192.168.1.1", null],
    ["172.20.0.1", null],
    ["169.254.1.1", null],
    ["256.1.1.1", null],
    ["01.2.3.4", null],
    ["localhost", null],
    ["", null],
    [".", null],
    ["a..b.com", null],
    [".example.com", null],
    ["-bad.example.com", null],
    ["bad-.example.com", null],
    [`${"a".repeat(64)}.com`, null],
    ["example.123", null],
    ["example.c", null],
    ["example.com/path", null],
    ["example.com:8080", null],
    ["example.com?x=1", null],
    ["user@example.com", null],
    ["*.example.com", null],
    ["exa mple.com", null],
    ["%20mandrillapp.com", null],
    ["[::1]", null],
    ["ex\u202Eample.com", null],
    [null, null],
  ];
  test("normalises or refuses", () => {
    for (const [raw, want] of cases) eq(normaliseHost(raw), want, `normaliseHost(${JSON.stringify(raw)})`);
  });

  test("the lookup walk goes down to two labels; an address is tried only whole", () => {
    eq(hostWalk("a.b.evil.net"), ["a.b.evil.net", "b.evil.net", "evil.net"]);
    eq(hostWalk("evil.net"), ["evil.net"]);
    eq(hostWalk("net"), []);
    eq(hostWalk("1.2.3.4"), ["1.2.3.4"]);
    eq(hostWalk("203.0.113.9"), ["203.0.113.9"], "never 0.113.9 or 113.9");
    eq(hostWalk("x.1.2.3.4"), ["x.1.2.3.4"], "a name ending in digits has no parents, as in the app's HostNames");
  });

  test("IPv6 literals are never hosts", () => {
    for (const raw of ["[2001:db8::1]", "2001:db8::1", "::1", "[::ffff:1.2.3.4]", "fe80::1%eth0"]) eq(normaliseHost(raw), null, raw);
  });

  test("names in other scripts use nontransitional UTS-46, the mode of the app's IcuIdna", () => {
    eq(readHost("faß.example"), { host: "xn--fa-hia.example", idna: "nontransitional" }, "ß kept, never fass");
    eq(readHost("FAẞ.example").host, "xn--fa-hia.example", "capital sharp s lower-cases to ß first");
    eq(readHost("ςa.example"), { host: "xn--a-xmb.example", idna: "nontransitional" }, "final sigma kept");
    eq(readHost("क्‍.example").idna, "nontransitional", "a joiner where CheckJoiners allows it");
    eq(readHost("a‍b.example").host, null, "a joiner where CheckJoiners refuses it");
    eq(readHost("Bücher.example"), { host: "xn--bcher-kva.example", idna: "converted" });
    eq(readHost("fass.example"), { host: "fass.example", idna: null });
    const icu = path.join(HERE, "..", "app/src/main/java/com/attnom/folio/tools/qr/IcuIdna.kt");
    if (existsSync(icu)) {
      const kt = readFileSync(icu, "utf8");
      for (const flag of ["NONTRANSITIONAL_TO_ASCII", "CHECK_CONTEXTJ", "CHECK_BIDI"]) ok(kt.includes(`IDNA.${flag}`), `IcuIdna.kt no longer sets ${flag}: hosts.mjs must follow the app's mode`);
    }
  });

  test("a lookup tries parent hosts and stops at two labels", () => {
    const table = openTable(writeTable({ labelled: false, entries: ["evil.net", "deep.sub.bad.org", "net", "9.9.9.9"].map((text) => ({ text })) }).bytes, "hosts");
    eq(hostListed(table, "evil.net"), true);
    eq(hostListed(table, "a.b.evil.net"), true);
    eq(hostListed(table, "b.evil.net"), true);
    eq(hostListed(table, "evilnet"), false);
    eq(hostListed(table, "notevil.net"), false);
    eq(hostListed(table, "evil.net.example.com"), false);
    eq(hostListed(table, "sub.bad.org"), false, "a parent is not listed because a child is");
    eq(hostListed(table, "x.deep.sub.bad.org"), true);
    eq(hostListed(table, "x.net"), false, "the single label net is never tried");
    eq(hostListed(table, "9.9.9.9"), true);
    eq(hostListed(table, "1.9.9.9"), false, "an address has no parents");
  });
});

describe("keep-list", () => {
  const keep = loadKeepList();
  const keeper = buildKeeper(keep);

  test("the shipped list is large, valid and has the sites that must never be warned about", () => {
    ok(keep.size >= 2000, `only ${keep.size} entries`);
    for (const host of ["google.com", "sbi.co.in", "hdfcbank.com", "paytm.com", "gov.in", "irctc.co.in", "microsoft.com", "amazon.in", "npci.org.in", "whatsapp.com", "apkpure.com", "getpocket.com"]) ok(keep.has(host), host);
    // User content and hosting: the name itself is never listed, a page below it may be.
    for (const host of ["blogspot.com", "github.io", "web.app", "pages.dev", "vercel.app", "netlify.app", "wordpress.com", "pastebin.com", "paste.ee", "firebasestorage.googleapis.com", "forms.gle", "typeform.com", "s3.amazonaws.com", "tiny.cc"]) eq(keep.get(host), true, `${host} is shared`);
    eq(keep.get("google.com"), false);
    for (const host of ["pastebin.com", "paste.ee", "firebasestorage.googleapis.com", "apkpure.com", "getpocket.com"]) ok(keeper.reason(host) !== null, `${host} cannot be listed`);
    eq(keeper.reason("someone.firebasestorage.googleapis.com"), null, "a deeper name on shared storage may be listed");
  });

  test("the file parses strictly", () => {
    fails(() => parseKeepList("example.com\nexample.com\n"), /twice/);
    fails(() => parseKeepList("Example.com\n"), /not "host"/);
    fails(() => parseKeepList("example.com sharedd\n"), /not "host"/);
    fails(() => parseKeepList("example.com shared extra\n"), /not "host"/);
    fails(() => parseKeepList("localhost\n"), /not "host"/);
    eq([...parseKeepList("# c\n\na.com shared # tail\nb.com\n")], [["a.com", true], ["b.com", false]]);
  });

  test("exact, below, parent, shared, nearest ancestor", () => {
    eq(keeper.reason("google.com")?.kind, "kept");
    eq(keeper.reason("docs.google.com")?.kind, "below");
    eq(keeper.reason("a.b.sbi.co.in")?.kind, "below");
    eq(keeper.reason("co.in")?.kind, "kept", "the suffix is a parent of a kept host");
    eq(keeper.reason("blogspot.com")?.kind, "kept");
    eq(keeper.reason("evil.blogspot.com"), null);
    eq(keeper.reason("a.evil.github.io"), null);
    eq(keeper.reason("x.westus.cloudapp.azure.com"), null, "shared inside a non-shared domain");
    eq(keeper.reason("portal.azure.com")?.kind, "below");
    eq(keeper.reason("google.com.evil.net"), null);
    eq(keeper.reason("notgoogle.com"), null);
    eq(keeper.reason("evil.co.in"), null);
  });

  test("a bad entry with the same key as a kept host is refused", () => {
    const k = buildKeeper(new Map([["kept.example", false]]), () => "same");
    eq(k.reason("other.example")?.kind, "clash");
  });

  test("applyKeepList counts what it drops", () => {
    const { kept, dropped } = applyKeepList(["docs.google.com", "evil.net", "x.docs.google.com", "bit.ly", "p.blogspot.com"], keeper);
    eq(kept, ["evil.net", "p.blogspot.com"]);
    eq(dropped.get("below google.com"), 2);
    eq(dropped.get("kept bit.ly"), 1);
  });
});

describe("app keep-lists", () => {
  const packages = loadKeepPackages();
  const certs = loadKeepCerts();

  test("the shipped package list protects the most installed apps and every system prefix", () => {
    ok(packages.exact.size >= 400, `only ${packages.exact.size} packages`);
    eq(packages.prefixes, ["android.", "com.android.", "com.google.android."]);
    for (const name of ["com.whatsapp", "com.facebook.katana", "com.instagram.android", "com.phonepe.app", "net.one97.paytm", "in.org.npci.upiapp", "com.sbi.lotusintouch", "com.truecaller", "com.miui.securitycenter", "com.sec.android.app.launcher", "org.telegram.messenger", "android"]) ok(packageRule(name, packages)?.rule, name);
    for (const name of ["com.android.vending", "com.android.chrome", "com.google.android.gms", "com.google.android.apps.nbu.paisa.user", "android.ext.services"]) eq(packageRule(name, packages)?.known, false, `${name} under a prefix`);
    eq(packageRule("com.mxspy", packages), null);
    eq(packageRule("com.microsoft.familysafety", packages), null, "a monitoring app the sources list on purpose stays listed");
    eq(packageRule("com.android.core.mngi", packages), { listed: true }, "a stalkerware name that imitates a system one");
  });

  test("the AOSP test certificates are kept, and the digests are the real ones", () => {
    // fixtures/aosp-certs holds the five .x509.pem files from build/make/target/product/security; recompute every digest.
    const dir = path.join(FIX, "aosp-certs");
    const names = ["testkey", "platform", "shared", "media", "networkstack"];
    for (const name of names) {
      const der = new X509Certificate(readFileSync(path.join(dir, `${name}.x509.pem`))).raw;
      for (const algorithm of ["sha1", "sha256"]) {
        const hex = createHash(algorithm).update(der).digest("hex");
        ok(certs.has(hex), `${name} ${algorithm} ${hex} is in keep-certs.txt`);
      }
    }
    eq(certs.size, names.length * 2, "nothing in keep-certs.txt that the fixtures cannot vouch for");
    eq(createHash("sha1").update(new X509Certificate(readFileSync(path.join(dir, "testkey.x509.pem"))).raw).digest("hex"), "61ed377e85d386a8dfee6b864bd85b0bfaa5af81");
    eq(certRule("61ed377e85d386a8dfee6b864bd85b0bfaa5af81", certs), { rule: "keep 61ed377e85d386a8dfee6b864bd85b0bfaa5af81", known: true });
  });

  test("the files parse strictly", () => {
    fails(() => parseKeepPackages("com.a\ncom.a\n"), /twice/);
    fails(() => parseKeepPackages("com.a extra\n"), /is not/);
    fails(() => parseKeepPackages("com.a known more\n"), /is not/);
    fails(() => parseKeepPackages("com.*.b\n"), /is not/);
    fails(() => parseKeepPackages("com.x.y listed\n"), /under no protected prefix/);
    eq(parseKeepPackages("a.*\na.b listed\nc.d known\n").exact.get("c.d"), { known: true });
    fails(() => parseKeepCerts("ABCDEF\n"), /is not/);
    fails(() => parseKeepCerts(`${"A".repeat(40)}\n`), /is not/);
    fails(() => parseKeepCerts(`${"a".repeat(40)}\n${"a".repeat(40)}\n`), /twice/);
    eq(parseKeepCerts(`${"a".repeat(64)} known\n`).get("a".repeat(64)), { known: true });
  });
});

describe("labels", () => {
  test("a name passes only the strict filter; anything else is the word for its kind", () => {
    eq(threatLabel("mSpy", "stalkerware"), "mSpy (stalkerware)");
    eq(threatLabel("Wise Mo_2.0-x", "watchware"), "Wise Mo_2.0-x (watchware)");
    eq(threatLabel("1TopSpy", "stalkerware"), "1TopSpy (stalkerware)");
    for (const [bad, why] of [
      ["Call +1 555 0100 to remove", "plus sign"],
      ["Call 5550100 now", "five digits in a row"],
      ["12345", "digits only"],
      ["x".repeat(31), "longer than 30"],
      ["visit http-site", "http"],
      ["www.remove-it.com", "www"],
      ["help@remove.it", "@"],
      ["Spy (pro)", "brackets"],
      ["Spy‮ware", "direction override"],
      ["Spуware", "a Cyrillic letter"],
      ["", "empty"],
      ["...", "no letter"],
    ]) {
      eq(safeName(bad), null, why);
      eq(threatLabel(bad, "stalkerware"), "Stalkerware", why);
    }
    eq(threatLabel("Call +1 555", "watchware"), "Monitoring app");
    eq(threatLabel("Call +1 555", "spyware"), "Spyware");
    eq(campaignLabel("Call_+1_555_0100"), "Spyware");
    eq(echapItems({ ioc: { apps: [{ name: "Call +1 555 0100", type: "stalkerware", packages: ["p.q"], sha1: [], sha256: [] }] }, watchware: { apps: [] }, samples: [] }).pkg[0].label, "Stalkerware");
  });

  test("what the app accepts unchanged: a plain name and a known kind", () => {
    for (const good of ["mSpy (stalkerware)", "Stalkerware", "Monitoring app", "Toolkit list check", "Cellebrite (forensic tool)", "Snoopza (name used by stalkerware)", "Name used by spyware", ...Object.values(MVT_LABELS)]) ok(labelAllowed(good), good);
    for (const bad of ["Call +1 555 (stalkerware)", "mSpy (malware)", "mSpy (stalkerware) ", "x".repeat(31), "a (stalkerware) (spyware)"]) eq(labelAllowed(bad), false, bad);
    eq(nameUsedLabel("Snoopza (stalkerware)"), "Snoopza (name used by stalkerware)");
    eq(nameUsedLabel("Morpheus (spyware)"), "Morpheus (name used by spyware)");
    eq(nameUsedLabel("Stalkerware"), "Name used by stalkerware");
    eq(labelAllowed(nameUsedLabel("x".repeat(30) + " (stalkerware)")), true);
  });

  test("the app's LabelText.shown applies the same rule (the source names the same kinds)", { skip: !existsSync(path.join(HERE, "..", "app/src/main/java/com/attnom/folio/security/defs/LabelText.kt")) && "LabelText.kt is not in this repository" }, () => {
    const kt = readFileSync(path.join(HERE, "..", "app/src/main/java/com/attnom/folio/security/defs/LabelText.kt"), "utf8");
    for (const [kind, generic] of Object.entries(KINDS)) ok(kt.includes(`"${kind}" to "${generic}"`), `LabelText.kt maps "${kind}" to "${generic}"`);
    ok(kt.includes(`NAME_MAX = ${NAME_MAX}`), "the same length limit");
  });
});

// ---- the YAML reader ---------------------------------------------------------------------------------------------

describe("yaml reader", () => {
  test("reads the shapes of the real files", () => {
    const doc = parseYaml(fixture("echap-ioc.yaml"), "ioc.yaml");
    eq(doc.map((e) => e.name), ["TheTruthSpy", "jjspy", "KidsShield", "MobiStealth", "SMSForward", "Ahmyth", "xHunter"]);
    const truth = doc[0];
    eq(truth.type, "stalkerware");
    eq(truth.packages.length, 10);
    eq(truth.packages[0], "com.apspy.app");
    eq(truth.certificates.length, 16);
    eq(truth.c2.ips.length, 5);
    eq(truth.c2.domains[0], "1ca43.appspot.com");
    eq(truth.distribution, ["app.fonetracker.com", "app.mobiletracking.app", "app.xpspy.com"], "list indented under its key");
    eq(doc[1].name, "jjspy", "a key written as `name : value`");
    eq(doc[2].certificate_cname_re, ["^Kids\\WSafety\\W[0-9]{2}-[0-9]{2}-[0-9]{2,4}\\W[0-9]{2}:[0-9]{2}:[0-9]{2}$"], "a colon inside a value");
    eq(doc[3].c2.ip, ["72.167.46.196", "5.79.71.114"]);
    eq(doc[6].certificates, undefined);
    eq(parseYaml(fixture("echap-watchware.yaml"), "watchware.yaml").length, 27);
  });

  test("scalars stay text; empty values are null; comments and quotes", () => {
    const doc = parseYaml("a: 123\nb: true\nc:\nd: 'it''s' # note\ne: \"x\\ty\"\nf: plain # tail\n");
    eq(doc.a, "123");
    eq(doc.b, "true");
    eq(doc.c, null);
    eq(doc.d, "it's");
    eq(doc.e, "x\ty");
    eq(doc.f, "plain");
    eq(parseYaml("# only a comment\n\n"), null);
    eq(Object.getPrototypeOf(parseYaml("__proto__: x\n")), null, "maps have no prototype to poison");
  });

  test("anything else stops with the line number", () => {
    const bad = (text, pattern) => fails(() => parseYaml(text, "f.yaml"), (e) => e instanceof YamlError && pattern.test(e.message));
    bad("a: [1, 2]\n", /line 1.*\[/);
    bad("a: {b: 1}\n", /line 1/);
    bad("a: &x 1\n", /line 1/);
    bad("a: *x\n", /line 1/);
    bad("a: |\n  text\n", /line 1/);
    bad("a: >\n  text\n", /line 1/);
    bad("a: !tag x\n", /line 1/);
    bad("a:\n\tb: 1\n", /line 2.*tab/);
    bad("a: 1\na: 2\n", /line 2.*twice/);
    bad("a: 1\n  b: 2\n", /line 2.*indentation/);
    bad("a: 'open\n", /line 1.*closed/);
    bad("a: 'x' y\n", /line 1.*after the closing quote/);
    bad("a: \"\\q\"\n", /line 1.*escape/);
    bad("---\na: 1\n", /line 1.*document markers/);
    bad("a: b: c\n", /line 1.*mapping/);
    bad("  a: 1\n", /line 1.*column 0/);
    bad("- a\nb: 1\n", /line 2/);
    bad("a: 1\n- b\n", /line 2/);
  });
});

// ---- Echap, MVT ---------------------------------------------------------------------------------------------------

describe("Echap files", () => {
  const ioc = parseEchapYaml(fixture("echap-ioc.yaml"), "stalkerware", "ioc.yaml");
  const watchware = parseEchapYaml(fixture("echap-watchware.yaml"), "watchware", "watchware.yaml");
  const samples = parseSamplesCsv(fixture("echap-samples.csv"), "samples.csv");

  test("reads apps, packages and certificates", () => {
    eq(ioc.apps.length, 7);
    eq(ioc.apps[0].packages.length, 10);
    eq(ioc.apps[0].sha1.length, 16);
    eq(ioc.apps[0].sha256, []);
    eq(watchware.apps.length, 27);
    eq(samples.length, 14);
    eq(samples[0].sha256, "2f3bc9ebe8c249f0416f5b0367f34b4b8f6aaa7d351dc5b4912fe2558491b6b7");
    eq(samples[0].app, "1TopSpy", "no stray carriage return");
    eq(samples.filter((s) => s.packageName === "").length, 4);
  });

  test("SHA-1 certificates go to apps-cert with their app's label", () => {
    const items = echapItems({ ioc, watchware, samples });
    ok(items.cert.length >= 16, `${items.cert.length} certificate rows`);
    ok(items.cert.every((c) => /^[0-9a-f]{40}$/.test(c.text)), "all SHA-1 in the fixtures, lower-case");
    const first = ioc.apps[0];
    eq(items.cert.find((c) => c.text === first.sha1[0])?.label, `${first.name} (stalkerware)`);
    ok(items.notes.some((n) => /SHA-1; apps-cert holds them/.test(n)));
    const table = openTable(writeTable({ keyBytes: 8, labelled: true, entries: items.cert }).bytes, "apps-cert");
    eq(lookupText(table, first.sha1[0]), `${first.name} (stalkerware)`);
    const sha256Cert = parseEchapYaml(`- name: X\n  type: stalkerware\n  certificates:\n  - ${"AB".repeat(32)}\n`, "stalkerware", "t.yaml");
    eq(echapItems({ ioc: sha256Cert, watchware: { apps: [] }, samples: [] }).cert, [{ text: "ab".repeat(32), label: "X (stalkerware)" }]);
  });

  test("labels, and the watchware label wins for a package in both files", () => {
    const items = echapItems({ ioc, watchware, samples });
    const label = (t) => items.pkg.find((i) => i.text === t)?.label;
    eq(label("com.mxspy"), "TheTruthSpy (stalkerware)");
    eq(label("com.wisemo.host.v10"), "WiseMo (watchware)");
    const both = echapItems({ ioc: { apps: [{ name: "Z", type: "stalkerware", packages: ["p.q"], sha1: [], sha256: [] }] }, watchware: { apps: [{ name: "Z", type: "watchware", packages: ["p.q"], sha1: [], sha256: [] }] }, samples: [] });
    const table = openTable(writeTable({ keyBytes: 8, labelled: true, entries: both.pkg }).bytes, "t");
    eq(lookupText(table, "p.q"), "Z (watchware)");
    eq(items.sha.length, 14);
    eq(items.sha[0].label, "1TopSpy (stalkerware)");
  });

  test("a changed shape fails loudly", () => {
    fails(() => parseEchapYaml("- name: X\n  type: other\n", "stalkerware", "ioc.yaml"), /type is "other"/);
    fails(() => parseEchapYaml("- type: stalkerware\n", "stalkerware", "ioc.yaml"), /no name/);
    fails(() => parseEchapYaml("- name: X\n  type: stalkerware\n  certificates:\n  - 12AB\n", "stalkerware", "ioc.yaml"), /neither SHA-1 nor SHA-256/);
    fails(() => parseEchapYaml("- name: X\n  type: stalkerware\n  packages: com.x\n", "stalkerware", "ioc.yaml"), /packages/);
    fails(() => parseEchapYaml("name: X\n", "stalkerware", "ioc.yaml"), /expected a list/);
    fails(() => parseSamplesCsv("Hash,Name\na,b\n", "s.csv"), /unexpected header/);
    fails(() => parseSamplesCsv("SHA256,Package Name,Certificate,Version,App\r\nabc,p.q,,1,X\r\n", "s.csv"), /not a SHA-256/);
    fails(() => parseSamplesCsv(`SHA256,Package Name,Certificate,Version,App\r\n${"a".repeat(64)},p.q,1\r\n`, "s.csv"), /fields/);
    fails(() => parseSamplesCsv(`SHA256,Package Name,Certificate,Version,App\r\n${"a".repeat(64)},"p,q",,1,X\r\n`, "s.csv"), /quoted/);
  });
});

describe("MVT indicators", () => {
  const index = parseIndex(fixture("mvt-indicators.yaml"));

  test("follows only the index entries from repositories with a recorded licence", () => {
    eq(index.files.length, 18, "19 entries, the Echap bundle left out");
    ok(index.files.every((f) => f.url.startsWith("https://raw.githubusercontent.com/")));
    eq(index.files.filter((f) => f.source === "amnesty").length, 4);
    ok(index.skipped.some((s) => /same data as the Echap files/.test(s)));
    const extra = `${fixture("mvt-indicators.yaml")}  -\n    type: github\n    name: Other\n    github:\n      owner: someone\n      repo: else\n      branch: main\n      path: x/y.stix2\n  -\n    type: url\n    name: Elsewhere\n`;
    const more = parseIndex(extra);
    eq(more.files.length, 18);
    ok(more.skipped.some((s) => /Other: someone\/else has no recorded licence/.test(s)));
    ok(more.skipped.some((s) => /Elsewhere: type "url"/.test(s)));
  });

  test("a path that could leave the repository is refused", () => {
    const entry = (p) => `indicators:\n  -\n    type: github\n    name: N\n    github:\n      owner: mvt-project\n      repo: mvt-indicators\n      branch: main\n      path: ${p}\n`;
    fails(() => parseIndex(entry("../x.stix2")), /plain/);
    fails(() => parseIndex(entry("a/b.txt")), /plain/);
    fails(() => parseIndex(entry("a%2Fb.stix2")), /plain/);
    fails(() => parseIndex("nothing: here\n"), /indicators/);
  });

  test("reads app ids, certificates, file hashes and domains; ignores the rest", () => {
    const rcs = parseStix(fixture("stix-rcs.json"), "rcs");
    eq(rcs.pkg.map((i) => i.label), ["RCS Lab (spyware)", "RCS Lab (spyware)", "RCS Lab (spyware)"]);
    eq(rcs.sha.length, 3);
    ok(rcs.sha.every((i) => /^[0-9a-f]{64}$/.test(i.text)));
    eq(rcs.hosts.length, 3);
    const novi = parseStix(fixture("stix-novispy.json"), "novispy");
    eq(novi.cert.length, 3);
    ok(novi.cert.every((i) => i.label === "NoviSpy (spyware)" && /^[0-9a-f]{64}$/.test(i.text)));
    const predator = parseStix(fixture("stix-predator.json"), "predator");
    eq([predator.pkg.length, predator.sha.length, predator.hosts.length], [0, 0, 2], "file paths and profile ids are not taken");
    eq(parseStix(fixture("stix-cellebrite.json"), "cb").pkg[0].label, "Cellebrite (forensic tool)");
  });

  test("labels name the campaign", () => {
    eq(campaignLabel("Predator"), "Predator (spyware)");
    eq(campaignLabel("RCSLab"), "RCS Lab (spyware)");
    eq(campaignLabel("WyrmSpy_DragonEgg"), "WyrmSpy and DragonEgg (spyware)");
    eq(campaignLabel("Wintego Helios"), "Wintego Helios (spyware)");
    eq(campaignLabel("Some_New_One"), "Some New One (spyware)");
  });

  test("odd input is counted or refused, never guessed", () => {
    const bundle = (objects) => JSON.stringify({ type: "bundle", id: "bundle--1", objects });
    const m = { type: "malware", id: "malware--1", name: "Alpha" };
    const ind = (id, pattern) => ({ type: "indicator", id, pattern, pattern_type: "stix" });
    const text = bundle([m, ind("indicator--1", "[app:cert.sha256='ABCDEF']"), ind("indicator--2", "[file:hashes.sha256='" + "AB".repeat(32) + "']"), ind("indicator--3", "[domain-name:value='x.example' OR domain-name:value='y.example']"), ind("indicator--4", "[app:id='bad name']")]);
    const parsed = parseStix(text, "t");
    eq([parsed.rejected, parsed.unparsed, parsed.sha.length, parsed.sha[0].text], [2, 1, 1, "ab".repeat(32)]);
    fails(() => parseStix(bundle([m, { type: "malware", id: "malware--2", name: "Beta" }, ind("indicator--1", "[app:id='a.b']")]), "t"), /no malware/);
    fails(() => parseStix("{", "t"), /not JSON/);
    fails(() => parseStix("{}", "t"), /not a STIX bundle/);
  });
});

// ---- signing -------------------------------------------------------------------------------------------------------

describe("signing", () => {
  const bytes = Buffer.from("manifest bytes\n");

  test("sign, verify, and refuse a changed file or another key", () => {
    const sig = signBytes(bytes, TEST_PRIVATE);
    eq(sig.length, 88);
    eq(signatureValid(bytes, sig, TEST_PUBLIC), true);
    eq(signatureValid(Buffer.from("manifest bytes\r\n"), sig, TEST_PUBLIC), false);
    eq(signatureValid(bytes, signBytes(bytes, OTHER_PRIVATE), TEST_PUBLIC), false);
    eq(signatureValid(bytes, "not base64", TEST_PUBLIC), false);
    eq(signatureValid(bytes, `${sig}\n`, TEST_PUBLIC), true, "a trailing newline is tolerated here, the app should trim too");
  });

  test("the key comes from a file or from text, and errors never show it", () => {
    const pem = TEST_PRIVATE.export({ format: "pem", type: "pkcs8" });
    const dir = mkdtempSync(path.join(tmpdir(), "defs-key-"));
    const file = path.join(dir, "k.pem");
    writeFileSync(file, pem);
    eq(privateKeyFromEnv({ TOOLKIT_DEFS_KEY_FILE: file }).asymmetricKeyType, "ed25519");
    eq(privateKeyFromEnv({ TOOLKIT_DEFS_KEY: pem }).asymmetricKeyType, "ed25519");
    eq(privateKeyFromEnv({ TOOLKIT_DEFS_KEY: pem.replace(/\n/g, "\\n") }).asymmetricKeyType, "ed25519", "one-line secret with \\n");
    eq(privateKeyFromEnv({}), null);
    const secret = "SECRET-TEXT-12345";
    fails(() => privateKeyFromEnv({ TOOLKIT_DEFS_KEY: secret }), (e) => !e.message.includes(secret) && /Ed25519/.test(e.message));
    const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey.export({ format: "pem", type: "pkcs8" });
    fails(() => privateKeyFromEnv({ TOOLKIT_DEFS_KEY: rsa }), /Ed25519/);
    fails(() => privateKeyFromEnv({ TOOLKIT_DEFS_KEY_FILE: path.join(dir, "missing.pem") }), /cannot be read/);
    rmSync(dir, { recursive: true, force: true });
    fails(() => publicKeyFrom("AAAA"), /32 bytes/);
  });

  test("a set signed by any listed key verifies; a key not on the list does not", () => {
    const second = generateKeyPairSync("ed25519");
    const third = generateKeyPairSync("ed25519");
    const keys = [TEST_PUBLIC, second.publicKey];
    eq(signedByAny(bytes, signBytes(bytes, TEST_PRIVATE), keys), 0);
    eq(signedByAny(bytes, signBytes(bytes, second.privateKey), keys), 1, "the backup key");
    eq(signedByAny(bytes, signBytes(bytes, third.privateKey), keys), -1, "a third key is refused");
    const bySecond = makeSet({ key: second.privateKey });
    eq(failing(checkSet(bySecond, options({ publicKey: keys }))), []);
    ok(/public key 2 of 2/.test(checkSet(bySecond, options({ publicKey: keys })).find((r) => r.gate === "signature").detail));
    eq(failing(checkSet(makeSet({ key: third.privateKey }), options({ publicKey: keys }))), ["signature"]);
    eq(failing(checkSet(bySecond, options())), ["signature"], "one key given: only that key");
    // The production list: two valid 32-byte keys, the daily one first.
    eq(PUBLIC_KEYS.length, 2);
    eq(PUBLIC_KEY, PUBLIC_KEYS[0]);
    eq(publicKeys().length, 2);
  });

  test("the public keys and the format constants match DefsFormat.kt", { skip: !existsSync(path.join(HERE, "..", "app/src/main/java/com/attnom/folio/security/defs/DefsFormat.kt")) && "DefsFormat.kt is not in this repository" }, () => {
    const kt = readFileSync(path.join(HERE, "..", "app/src/main/java/com/attnom/folio/security/defs/DefsFormat.kt"), "utf8");
    const get = (re) => kt.match(re)?.[1];
    eq([...(get(/val PUBLIC_KEYS = listOf\(([^)]+)\)/) ?? "").matchAll(/"([^"]+)"/g)].map((m) => m[1]), PUBLIC_KEYS);
    eq(get(/const val KEY_BYTES = (\d+)/), "8");
    eq(get(/const val MAX_AHEAD_MS = ([^\n]+)/), "2L * 24 * 60 * 60 * 1000");
    eq(get(/const val BASE_URL = "([^"]+)"/), PUBLISHED_BASE);
    eq(get(/const val MAGIC = "([^"]+)"/), "TKL1");
    eq(get(/const val HEADER_BYTES = (\d+)/), "16");
    eq(get(/const val MAX_LABEL = (\d+)/), "60");
    eq(get(/const val FORMAT = (\d+)/), "1");
    eq(get(/const val MAX_MANIFEST_BYTES = ([^\n]+)/), "64 * 1024");
    eq(get(/const val MAX_TOTAL_BYTES = ([^\n]+)/), "12L * 1024 * 1024");
    eq([get(/APPS_BY_PACKAGE = "([^"]+)"/), get(/APPS_BY_CERT = "([^"]+)"/), get(/APPS_BY_FILE = "([^"]+)"/), get(/HOSTS = "([^"]+)"/)], FILES.map((f) => f.name));
    eq(get(/const val MANIFEST = "([^"]+)"/), "manifest.json");
    eq(get(/const val SIGNATURE = "([^"]+)"/), "manifest.json.sig");
  });
});

// ---- the gates, each failing on crafted bad input ----------------------------------------------------------

describe("gates", () => {
  test("a good set passes every check", () => {
    const results = checkSet(makeSet(), options());
    eq(failing(results), []);
    eq(results.map((r) => r.gate), ["manifest", "signature", "files", "tables", "labels", "canaries", "sizes", "keep-list"]);
  });

  test("a label that is not a plain name", () => {
    const shouting = makeSet({ pkg: [{ text: "com.x.y", label: "Call +1 555 0100 to remove" }] });
    eq(failing(checkSet(shouting, options())), ["labels"]);
    ok(/Call \+1 555 0100/.test(checkSet(shouting, options()).find((r) => r.gate === "labels").detail));
  });

  test("a table without its canary", () => {
    const results = checkSet(makeSet({ canaries: false }), options());
    eq(failing(results), ["canaries"]);
    const detail = results.find((r) => r.gate === "canaries").detail;
    for (const name of ["apps-pkg.tkl", "apps-cert.tkl", "apps-sha.tkl", "hosts.tkl"]) ok(detail.includes(name), `${name} named`);
    const wrongLabel = makeSet({ pkg: [{ text: CANARY.package, label: "Something else" }, ...TINY.pkg], canaries: false, cert: withCanary("cert", TINY.cert), sha: withCanary("sha", TINY.sha), hosts: [CANARY.host, ...TINY.hosts] });
    eq(failing(checkSet(wrongLabel, options())), ["canaries"], "the package canary has the wrong label");
  });

  test("zero entries from a source", () => {
    const rows = [{ id: "a", min: 10 }, { id: "b", min: 1 }];
    const per = new Map([["a", { pkg: 0, cert: 0, sha: 0, hosts: 0, rejected: 0, raw: 0 }], ["b", { pkg: 1, cert: 0, sha: 0, hosts: 0, rejected: 0, raw: 1 }]]);
    eq(failing(sourceGates(per, rows, 0.05)), ["source a"]);
    eq(failing(sourceGates(new Map(), [{ id: "gone", min: 1 }], 0.05)), ["source gone"]);
  });

  test("too many unusable entries", () => {
    const per = new Map([["a", { pkg: 90, cert: 0, sha: 0, hosts: 0, rejected: 10, raw: 100 }]]);
    eq(failing(sourceGates(per, [{ id: "a", min: 1 }], 0.05)), ["unusable a"]);
    eq(failing(sourceGates(per, [{ id: "a", min: 1 }], 0.2)), []);
  });

  test("a big drop against the previous set", () => {
    const prev = parseManifest(makeSet().manifestBytes);
    eq(prev.files.map((f) => f.entries), [4, 3, 2, 6], "canaries are counted in the manifest's entries, as the app counts them");
    const files = (hosts) => prev.files.map((f) => ({ name: f.name, entries: f.name === "hosts.tkl" ? hosts : f.entries }));
    const same = previousGates(files(6), 2026010102, prev, { maxDrop: 0.3, allowDrop: false });
    eq(failing(same), []);
    const dropped = previousGates([{ name: "apps-pkg.tkl", entries: 1 }, ...files(6).slice(1)], 2026010102, prev, { maxDrop: 0.3, allowDrop: false });
    eq(failing(dropped), ["drop"]);
    ok(/apps-pkg\.tkl 4 -> 1/.test(dropped.find((r) => r.gate === "drop").detail));
    eq(failing(previousGates([{ name: "apps-pkg.tkl", entries: 1 }, ...files(6).slice(1)], 2026010102, prev, { maxDrop: 0.3, allowDrop: true })), [], "--allow-drop");
    const total = { version: 2026010101, files: [{ name: "hosts.tkl", entries: 100 }] };
    eq(failing(previousGates([{ name: "hosts.tkl", entries: 69 }], 2026010102, total, { maxDrop: 0.3, allowDrop: false })), ["drop"]);
    eq(failing(previousGates([{ name: "hosts.tkl", entries: 71 }], 2026010102, total, { maxDrop: 0.3, allowDrop: false })), []);
    eq(failing(previousGates([], 2026010102, total, { maxDrop: 0.3, allowDrop: false })), ["drop"], "a file that vanished");
    eq(failing(previousGates(files(6), 2026010101, prev, { maxDrop: 0.3, allowDrop: false })), ["version"], "same version");
    eq(failing(previousGates(files(6), 2025123101, prev, { maxDrop: 0.3, allowDrop: false })), ["version"], "lower version");
    eq(failing(previousGates(files(3), 1, null, { maxDrop: 0.3, allowDrop: false })), []);
  });

  test("sudden growth of the app entries against the previous set", () => {
    const prev = { version: 2026010101, built: "2026-01-01T00:00:00Z", files: [{ name: "apps-pkg.tkl", entries: 60 }, { name: "apps-cert.tkl", entries: 40 }, { name: "hosts.tkl", entries: 1000 }] };
    const at = (pkg, hosts = 1000) => [{ name: "apps-pkg.tkl", entries: pkg }, { name: "apps-cert.tkl", entries: 40 }, { name: "hosts.tkl", entries: hosts }];
    const opts = { maxDrop: 0.3, allowDrop: false, maxGrowth: 0.25, now: Date.parse("2026-01-02T00:00:00Z") };
    eq(failing(previousGates(at(85), 2026010201, prev, opts)), [], "100 -> 125 is the limit");
    const grew = previousGates(at(86), 2026010201, prev, opts);
    eq(failing(grew), ["growth"]);
    ok(/app entries 100 -> 126 \(26\.0%\); more than 25% up/.test(grew.find((r) => r.gate === "growth").detail));
    eq(failing(previousGates(at(86), 2026010201, prev, { ...opts, allowGrowth: true })), [], "--allow-growth");
    eq(failing(previousGates(at(60, 5000), 2026010201, prev, opts)), [], "hosts may grow: only app entries count");
  });

  test("a previous set dated ahead of the build does not set the floor", () => {
    const ahead = { version: 2099010101, built: "2099-01-01T00:00:00Z", files: [{ name: "hosts.tkl", entries: 10 }] };
    const now = Date.parse("2026-11-12T06:00:00Z");
    const results = previousGates([{ name: "hosts.tkl", entries: 10 }], 2026111201, ahead, { maxDrop: 0.3, allowDrop: false, now });
    eq(failing(results), []);
    ok(/dated ahead of this build; phones refuse it/.test(results.find((r) => r.gate === "version").detail));
    const twoDays = { version: 2026111401, built: "2026-11-14T05:00:00Z", files: [{ name: "hosts.tkl", entries: 10 }] };
    eq(failing(previousGates([{ name: "hosts.tkl", entries: 10 }], 2026111201, twoDays, { maxDrop: 0.3, allowDrop: false, now })), ["version"], "within two days it is still the floor");
    eq(datedAhead({ version: 2026111501, built: "2026-11-12T00:00:00Z" }, now), true, "by the version's day");
    eq(datedAhead({ version: 2026111201, built: "2026-11-15T00:00:00Z" }, now), true, "by the built time");
    eq(datedAhead({ version: 2026111401, built: "2026-11-14T05:00:00Z" }, now), false);
  });

  test("the app keep-lists: dropped and named, and too many new hits stop the build", () => {
    const drop = (text, known = false, table = "pkg") => ({ table, text, label: "X (stalkerware)", source: "echap", rule: `keep ${text}`, known });
    eq(failing([appKeepGate([])]), []);
    eq(failing([appKeepGate([drop("61ed377e85d386a8dfee6b864bd85b0bfaa5af81", true, "cert"), drop("61ed377e85d386a8dfee6b864bd85b0bfaa5af81", true, "cert")])]), [], "a known hit, twice, is one and not new");
    const three = appKeepGate([drop("com.whatsapp"), drop("com.a.b"), drop("com.c.d")]);
    eq(failing([three]), [], `${MAX_NEW_HITS} new hits are dropped and printed`);
    ok(/package com\.whatsapp \(X \(stalkerware\); from echap; keep com\.whatsapp, NEW\)/.test(three.detail), three.detail);
    const four = appKeepGate([drop("com.whatsapp"), drop("com.a.b"), drop("com.c.d"), drop("com.e.f")]);
    eq(failing([four]), ["app keep-lists"]);
    ok(/4 new \(at most 3\): a source may have been tampered with/.test(four.detail), four.detail);
  });

  test("the host budget is never cut silently", () => {
    eq(failing([hostBudgetGate({ cap: 10, wanted: 10, over: new Map() })]), []);
    const over = hostBudgetGate({ cap: 10, wanted: 13, over: new Map([["phishing", 3]]) });
    eq(failing([over]), ["host budget"]);
    ok(/13 hosts for 10 places; over by 3 \(phishing 3\)/.test(over.detail), over.detail);
  });

  test("new certificate entries against the previous set are printed one by one", () => {
    const previous = makeSet();
    const lines = newCertificateLines([...TINY.cert, { text: "ab".repeat(20), label: "New (stalkerware)" }], previous);
    eq(lines, ["certificates: 1 new against the previous set", `new certificate entry: ${"ab".repeat(20)} New (stalkerware)`]);
    eq(newCertificateLines(TINY.cert, null), ["certificates: no previous set, 2 entries not compared"]);
  });

  test("a keep-list host in the table", () => {
    const keep = new Map([["google.com", false], ["blogspot.com", true]]);
    eq(failing(checkSet(makeSet({ hosts: ["evil.example", "google.com"] }), options({ keep }))), ["keep-list"]);
    eq(failing(checkSet(makeSet({ hosts: ["evil.example"] }), options({ keep }))), []);
    eq(failing(checkSet(makeSet({ hosts: ["blogspot.com"] }), options({ keep }))), ["keep-list"]);
    eq(failing(checkSet(makeSet({ hosts: ["evil.blogspot.com"] }), options({ keep }))), []);
    eq(failing(checkSet(makeSet({ hosts: ["www.google.com"] }), options({ keep }))), [], "listing a child does not make the parent listed");
    eq(failing(checkSet(makeSet({ hosts: [] }), options({ keep: new Map([["x.test", false]]) }))), []);
    const keeper = buildKeeper(keep);
    eq(failing([keepRescan(["evil.example"], keeper)]), []);
    eq(failing([keepRescan(["evil.example", "docs.google.com"], keeper)]), ["keep-list rescan"]);
  });

  test("a duplicate key and an unsorted table", () => {
    const flip = (mutator) => (set) => {
      const bytes = Buffer.from(set.files.get("hosts.tkl"));
      mutator(bytes);
      set.files.set("hosts.tkl", bytes);
      // Keep the manifest honest about the damaged file so only the table gate speaks.
      const m = JSON.parse(set.manifestBytes.toString());
      const entry = m.files.find((f) => f.name === "hosts.tkl");
      entry.sha256 = sha256Hex(bytes);
      set.manifestBytes = Buffer.from(`${JSON.stringify(m, null, 2)}\n`);
      set.signature = signBytes(set.manifestBytes, TEST_PRIVATE);
    };
    // Damage can also hide a canary, so the canary gate may speak as well; the table gate must.
    const dup = checkSet(makeSet({ mutate: flip((b) => b.copy(b, 24, 16, 24)) }), options());
    ok(failing(dup).includes("tables") && failing(dup).every((g) => g === "tables" || g === "canaries"), failing(dup).join());
    ok(/same key/.test(dup.find((r) => r.gate === "tables").detail));
    const unsorted = checkSet(makeSet({ mutate: flip((b) => { const first = Buffer.from(b.subarray(16, 24)); b.copy(b, 16, 24, 32); first.copy(b, 24); }) }), options());
    ok(failing(unsorted).includes("tables") && failing(unsorted).every((g) => g === "tables" || g === "canaries"), failing(unsorted).join());
    ok(/sorts before/.test(unsorted.find((r) => r.gate === "tables").detail));
    const badLabel = (set) => { const b = Buffer.from(set.files.get("apps-sha.tkl")); b.writeUInt16BE(9, 16 + 8); set.files.set("apps-sha.tkl", b); const m = JSON.parse(set.manifestBytes.toString()); m.files.find((f) => f.name === "apps-sha.tkl").sha256 = sha256Hex(b); set.manifestBytes = Buffer.from(`${JSON.stringify(m, null, 2)}\n`); set.signature = signBytes(set.manifestBytes, TEST_PRIVATE); };
    ok(failing(checkSet(makeSet({ mutate: badLabel }), options())).includes("tables"));
  });

  test("a wrong hash, size, count, extra file, missing file", () => {
    const wrongHash = checkSet(makeSet({ mutate: (s) => { const b = Buffer.from(s.files.get("hosts.tkl")); b[20] ^= 1; s.files.set("hosts.tkl", b); } }), options());
    ok(failing(wrongHash).includes("files"));
    ok(/SHA-256 differs/.test(wrongHash.find((r) => r.gate === "files").detail));
    ok(/bytes, manifest says/.test(checkSet(makeSet({ mutate: (s) => s.files.set("hosts.tkl", Buffer.concat([s.files.get("hosts.tkl"), Buffer.from([0])])) }), options()).find((r) => r.gate === "files").detail));
    ok(/is listed but missing/.test(checkSet(makeSet({ mutate: (s) => s.files.delete("apps-pkg.tkl") }), options()).find((r) => r.gate === "files").detail));
    ok(/not in the manifest/.test(checkSet(makeSet({ mutate: (s) => s.files.set("extra.tkl", Buffer.alloc(16)) }), options()).find((r) => r.gate === "files").detail));
    // The manifest claims another entry count than the table holds.
    const lying = makeSet();
    const m = JSON.parse(lying.manifestBytes.toString());
    m.files[3].entries -= 1;
    lying.manifestBytes = Buffer.from(`${JSON.stringify(m, null, 2)}\n`);
    lying.signature = signBytes(lying.manifestBytes, TEST_PRIVATE);
    ok(/manifest says/.test(checkSet(lying, options()).find((r) => r.gate === "files").detail));
    // A required table is not listed.
    const withoutHosts = makeSet();
    const m2 = JSON.parse(withoutHosts.manifestBytes.toString());
    m2.files = m2.files.filter((f) => f.name !== "hosts.tkl");
    withoutHosts.manifestBytes = Buffer.from(`${JSON.stringify(m2, null, 2)}\n`);
    withoutHosts.signature = signBytes(withoutHosts.manifestBytes, TEST_PRIVATE);
    withoutHosts.files.delete("hosts.tkl");
    ok(/hosts\.tkl is required/.test(checkSet(withoutHosts, options()).find((r) => r.gate === "manifest").detail), "refused by the manifest rules, as the app does");
  });

  test("a bad signature", () => {
    eq(failing(checkSet(makeSet({ key: OTHER_PRIVATE }), options())), ["signature"]);
    eq(failing(checkSet(makeSet({ mutate: (s) => (s.manifestBytes = Buffer.concat([s.manifestBytes, Buffer.from(" ")])) }), options())), ["signature"], "a changed manifest");
    eq(failing(checkSet(makeSet({ key: null }), options())), ["signature"], "missing signature");
    eq(failing(checkSet(makeSet({ key: null }), options({ requireSignature: false }))), [], "unsigned is allowed only when not required");
    eq(failing(checkSet(makeSet({ mutate: (s) => (s.signature = "AAAA") }), options())), ["signature"]);
  });

  test("a bad manifest stops everything else", () => {
    const good = JSON.parse(makeSet().manifestBytes.toString());
    const withEdit = (edit) => {
      const m = structuredClone(good);
      edit(m);
      return Buffer.from(JSON.stringify(m));
    };
    for (const [edit, pattern] of [
      [(m) => (m.format = 2), /format/],
      [(m) => (m.version = 5), /yyyymmddNN/],
      [(m) => (m.built = "yesterday"), /UTC time/],
      [(m) => (m.files = []), /no files/],
      [(m) => (m.files[0].name = "../x.tkl"), /plain \.tkl name/],
      [(m) => (m.files[0].sha256 = "ABC"), /sha256/],
      [(m) => (m.files[0].bytes = -1), /whole numbers/],
      [(m) => (m.files[1] = m.files[0]), /twice/],
      [(m) => m.files.push(m.files[0]), /5 files, at most 4/],
      [(m) => (m.sources = [{ name: "x" }]), /has no "licence"/],
      [(m) => (m.sources[0].name = ""), /missing name/],
      // The rules the app's DefsManifest adds:
      [(m) => (m.extra = 1), /unknown key "extra"/],
      [(m) => (m.files[0].note = "x"), /a file has an unknown key "note"/],
      [(m) => (m.sources[0].homepage = "https://x.test/"), /a source has an unknown key "homepage"/],
      [(m) => (m.version = 2026023001), /not a real date/],
      [(m) => (m.version = 2019123101), /not a real date/],
      [(m) => (m.version = 2100010101), /not a real date/],
      [(m) => (m.built = "2019-12-31T23:59:59Z"), /before 2020/],
      [(m) => (m.built = "2026-01-01T00:00:00.12Z"), /UTC time/],
      [(m) => (m.files[0].name = "other.tkl"), /the app knows/],
      [(m) => (m.files[0].bytes = 16), /out of range/],
      [(m) => (m.files[0].entries = 0), /cannot fit/],
      [(m) => (m.files[0].entries = 1000), /cannot fit/],
      [(m) => (m.files = m.files.filter((f) => f.name !== "hosts.tkl")), /hosts\.tkl is required/],
      [(m) => (m.sources = []), /no sources/],
      [(m) => (m.sources[0].url = "http://example.invalid/"), /plain https address/],
      [(m) => (m.sources[0].url = "https://example.invalid/a b"), /plain https address/],
      [(m) => (m.sources[0].licence = "x".repeat(41)), /at most 40/],
      [(m) => (m.sources[0].name = "a‮b"), /plain text/],
    ]) fails(() => parseManifest(withEdit(edit)), pattern);
    eq(parseManifest(withEdit((m) => (m.built = "2026-01-01T00:00:00.123Z"))).built, "2026-01-01T00:00:00.123Z", "milliseconds as toISOString writes them");
    eq(parseManifest(withEdit((m) => (m.files = m.files.filter((f) => f.name !== "apps-sha.tkl")))).files.length, 3, "apps-sha.tkl may be absent");
    fails(() => parseManifest(Buffer.from("nope")), /not JSON/);
    fails(() => parseManifest(Buffer.alloc(LIMITS.manifestBytes + 1, 32)), /over the/);
    const broken = checkSet({ manifestBytes: Buffer.from("{"), signature: null, files: new Map() }, options());
    eq(failing(broken), ["manifest"]);
    eq(broken.length, 1);
  });

  test("size limits", () => {
    const before = { ...LIMITS };
    try {
      LIMITS.hostsBytes = 30;
      eq(failing(checkSet(makeSet(), options())), ["sizes"]);
      LIMITS.hostsBytes = before.hostsBytes;
      LIMITS.totalBytes = 100;
      const overTotal = checkSet(makeSet(), options());
      eq(failing(overTotal), ["manifest"], "the manifest's own sizes are past the limit, as the app checks them");
      ok(/out of range|more than 100/.test(overTotal[0].detail), overTotal[0].detail);      LIMITS.totalBytes = before.totalBytes;
      LIMITS.manifestBytes = 100;
      eq(failing(checkSet(makeSet(), options())).includes("manifest"), true, "an oversize manifest is refused by the parser");
    } finally {
      Object.assign(LIMITS, before);
    }
    eq([LIMITS.manifestBytes, LIMITS.totalBytes, LIMITS.hostsBytes], [64 * 1024, 12 * 1024 * 1024, 6 * 1024 * 1024]);
    eq(maxHostEntries(), 786430, "8-byte keys in a 6 MB budget");
  });

  test("a table with the wrong shape for its name", () => {
    const wrongShape = makeSet({ mutate: (s) => { const t = writeTable({ labelled: true, entries: [{ text: "x.y", label: "X" }] }); s.files.set("hosts.tkl", t.bytes); const m = JSON.parse(s.manifestBytes.toString()); const e = m.files.find((f) => f.name === "hosts.tkl"); e.sha256 = sha256Hex(t.bytes); e.bytes = t.bytes.length; e.entries = 1; s.manifestBytes = Buffer.from(`${JSON.stringify(m, null, 2)}\n`); s.signature = signBytes(s.manifestBytes, TEST_PRIVATE); } });
    ok(/key\/value bytes 8\/2, expected 8\/0/.test(checkSet(wrongShape, options()).find((r) => r.gate === "files").detail));
  });

  test("a manifest whose host entries need 6-byte keys to fit is refused", () => {
    // The first format's bundled set: 521547 hosts in 3129298 bytes. At 8 bytes a key they cannot fit.
    const m = JSON.parse(makeSet().manifestBytes.toString());
    const hosts = m.files.find((f) => f.name === "hosts.tkl");
    hosts.entries = 521547;
    hosts.bytes = 3129298;
    fails(() => parseManifest(Buffer.from(JSON.stringify(m))), /hosts\.tkl: 521547 entries cannot fit in 3129298 bytes/);
  });
});

// ---- the fixture set -----------------------------------------------------------------------------------------------

describe("tiny fixture set", () => {
  const dir = path.join(FIX, "tiny-set");
  const set = makeSet();
  const queries = [
    ["package", "com.alpha.spy", "Alpha (stalkerware)"],
    ["package", "com.beta.watch", "Beta (watchware)"],
    ["package", "com.gamma.rat", "Alpha (stalkerware)"],
    ["package", "com.alpha.Spy", null],
    ["cert", "0123456789abcdef".repeat(4), "Delta (spyware)"],
    ["cert", "0123456789ABCDEF".repeat(4), "Delta (spyware)"],
    ["cert", "f".repeat(64), null],
    ["cert", "89abcdef01".repeat(4), "Zeta (stalkerware)"],
    ["cert", "89ABCDEF01".repeat(4), "Zeta (stalkerware)"],
    ["cert", "89abcdef01".repeat(4).slice(0, 39), null],
    ["cert", CANARY.hex, CANARY.label],
    ["package", CANARY.package, CANARY.label],
    ["sha", CANARY.hex, CANARY.label],
    ["sha", sha256Hex("tiny apk"), "Epsilon (spyware)"],
    ["sha", sha256Hex("other apk"), null],
    ["host", "evil.example", true],
    ["host", "login.evil.example", true],
    ["host", "a.b.evil.example", true],
    ["host", "BÜCHER.example", true],
    ["host", "www.xn--bcher-kva.example", true],
    ["host", "bad.test", true],
    ["host", "good.example", false],
    ["host", "example", false],
    ["host", "notevil.example", false],
    ["host", CANARY.host, true],
    ["host", `www.${CANARY.host}`, true],
    ["host", "203.0.113.9", true],
    ["host", "203.0.113.10", false],
    ["host", "203.0.113.90", false],
    ["host", "x.203.0.113.9", false],
    ["host", "faß.example", true],
    ["host", "fass.example", false],
    ["host", "[2001:db8::1]", false],
  ];

  test("is written to fixtures/tiny-set and is the same on every run", () => {
    mkdirSync(dir, { recursive: true });
    const wanted = new Map([...set.files, ["manifest.json", set.manifestBytes], ["manifest.json.sig", Buffer.from(set.signature)], ["public-key.txt", Buffer.from(`${TEST_PUBLIC_B64}\n`)]]);
    for (const [name, bytes] of wanted) {
      const target = path.join(dir, name);
      if (existsSync(target)) eq(readFileSync(target).equals(bytes), true, `${name} differs from the committed fixture; delete tiny-set to regenerate`);
      else writeFileSync(target, bytes);
    }
    // For a host, ascii is the form the app looks up (normalised as the writer does; null when it is not a usable host).
    const expected = queries.map(([kind, value, found]) => (kind === "host" ? { kind, value, ascii: normaliseHost(value), found } : { kind, value, found }));
    writeFileSync(path.join(dir, "expected.json"), `${JSON.stringify({ note: "Answers for the lists in this folder. found is the label, true for a listed host, false or null for none. A host is looked up by its ascii form, the name lower-cased and made punycode by nontransitional UTS-46. The public key is public-key.txt.", queries: expected }, null, 2)}\n`);
    eq(failing(checkSet(readSet(dir), options({ publicKey: publicKeyFrom(readFileSync(path.join(dir, "public-key.txt"), "utf8").trim()) }))), []);
    eq(parseManifest(readFileSync(path.join(dir, "manifest.json"))).version, 2026010101);
  });

  test("lookups answer as expected.json says", () => {
    for (const [kind, value, found] of queries) {
      const answer = lookupIn(dir, kind, value);
      eq(kind === "host" ? answer.found !== null : answer.found, found, `${kind} ${value}`);
    }
  });

  test("the command line verifies and looks up, and fails when it should", () => {
    const run = (...args) => spawnSync(process.execPath, [path.join(HERE, "threat-data.mjs"), ...args], { encoding: "utf8" });
    const verify = run("verify", dir);
    eq(verify.status, 1, "signed with the test key, not the real one");
    ok(/FAIL {2}signature/.test(verify.stdout));
    ok(/PASS {2}files/.test(verify.stdout));
    eq(run("lookup", dir, "package", "com.alpha.spy").status, 0);
    ok(/Alpha \(stalkerware\)/.test(run("lookup", dir, "package", "com.alpha.spy").stdout));
    eq(run("lookup", dir, "package", "com.none.here").status, 1);
    eq(run("lookup", dir, "host", "x.evil.example").status, 0);
    eq(run("lookup", dir, "wat", "x").status, 1);
    eq(run("verify").status, 1);
    eq(run("build").status, 1, "build needs --out");
    eq(run("nonsense").status, 1);
  });

  test("lookup answers for a missing folder or file", () => {
    eq(lookupIn(path.join(dir, "missing"), "host", "a.b").found, null);
    eq(lookupIn(dir, "host", "not a host").found, null);
    fails(() => lookupIn(dir, "wat", "x"), /unknown kind/);
    fails(() => readSet(path.join(dir, "missing")), /no manifest\.json/);
  });
});

// ---- a set written by the app's test-side writer -------------------------------------------------------------------------
// ReaderWrittenSetTest (app/src/test/.../security/defs) writes fixtures/reader-set with the app's TklWriter and TestSets,
// which share no code with this script. Reading it here checks the format from the other direction.

describe("set written by the app's tests", () => {
  const dir = path.join(FIX, "reader-set");

  test("verifies and answers as its expected.json says", () => {
    ok(existsSync(path.join(dir, "manifest.json")), "fixtures/reader-set is missing: run ReaderWrittenSetTest in the app's unit tests");
    const publicKey = publicKeyFrom(readFileSync(path.join(dir, "public-key.txt"), "utf8").trim());
    eq(failing(checkSet(readSet(dir), options({ publicKey }))), []);
    const { queries } = JSON.parse(readFileSync(path.join(dir, "expected.json"), "utf8"));
    ok(queries.length >= 10, `${queries.length} queries`);
    for (const { kind, value, found } of queries) {
      const answer = lookupIn(dir, kind, value);
      eq(kind === "host" ? answer.found !== null : answer.found, found, `${kind} ${value}`);
    }
  });
});

// ---- downloads ---------------------------------------------------------------------------------------------------------

describe("downloads", () => {
  const reply = (body, { status = 200, url, headers = {} } = {}) => ({ ok: status < 300, status, url, headers: { get: (k) => headers[k.toLowerCase()] ?? null }, body: (async function* () { yield Buffer.from(body); })() });

  test("refuses anything but https from the listed hosts", async () => {
    const fetchText = makeFetcher({ fetchImpl: async () => reply("x"), delayMs: 0 });
    await assert.rejects(fetchText("http://raw.githubusercontent.com/x", 100), /refusing/);
    await assert.rejects(fetchText("https://example.com/x", 100), /refusing/);
    await assert.rejects(fetchText("https://raw.githubusercontent.com.evil.net/x", 100), /refusing/);
    checks += 3;
    eq(await fetchText("https://raw.githubusercontent.com/x", 100), "x");
  });

  test("errors name the URL and the status", async () => {
    const fetchText = makeFetcher({ fetchImpl: async () => reply("", { status: 404 }), delayMs: 0 });
    await assert.rejects(fetchText("https://raw.githubusercontent.com/a/b", 100), /raw\.githubusercontent\.com\/a\/b: HTTP 404/);
    checks++;
  });

  test("tries again on a server error or a dropped connection, then gives up", async () => {
    let calls = 0;
    const flaky = makeFetcher({ fetchImpl: async () => (++calls < 3 ? reply("", { status: 503 }) : reply("fine")), delayMs: 0 });
    eq(await flaky("https://hole.cert.pl/x", 100), "fine");
    eq(calls, 3);
    let dropped = 0;
    const drops = makeFetcher({ fetchImpl: async () => { dropped++; throw Object.assign(new TypeError("fetch failed"), { cause: { code: "ECONNRESET" } }); }, delayMs: 0 });
    await assert.rejects(drops("https://hole.cert.pl/x", 100), /hole\.cert\.pl\/x: ECONNRESET/);
    eq(dropped, 3);
    let calls404 = 0;
    await assert.rejects(makeFetcher({ fetchImpl: async () => (calls404++, reply("", { status: 404 })), delayMs: 0 })("https://hole.cert.pl/x", 100), /HTTP 404/);
    eq(calls404, 1, "a 404 is not retried");
    checks += 3;
  });

  test("the size cap, declared and actual, and a redirect to another host", async () => {
    await assert.rejects(makeFetcher({ fetchImpl: async () => reply("x", { headers: { "content-length": "999" } }) })("https://hole.cert.pl/x", 100), /over the 100 byte limit/);
    await assert.rejects(makeFetcher({ fetchImpl: async () => reply("x".repeat(500)) })("https://hole.cert.pl/x", 100), /more than 100 bytes/);
    await assert.rejects(makeFetcher({ fetchImpl: async () => reply("x", { url: "https://evil.net/x" }) })("https://hole.cert.pl/x", 100), /redirected to https:\/\/evil\.net/);
    checks += 3;
  });
});

// ---- the whole build on fixtures ---------------------------------------------------------------------------------------

describe("build", () => {
  const STIX = {
    "intellexa_predator/predator.stix2": "stix-predator.json",
    "2022-06-23_rcs_lab/rcs.stix2": "stix-rcs.json",
    "cellebrite/cellebrite.stix2": "stix-cellebrite.json",
    "2024-12-16_serbia_novispy/novispy.stix2": "stix-novispy.json",
  };
  const answers = new Map([
    [URLS.echapIoc, fixture("echap-ioc.yaml")],
    [URLS.echapWatchware, fixture("echap-watchware.yaml")],
    [URLS.echapSamples, fixture("echap-samples.csv")],
    [URLS.mvtIndex, fixture("mvt-indicators.yaml")],
    [URLS.phishing, fixture("phishing-domains.txt")],
    [URLS.certPl, fixture("certpl-domains.txt")],
  ]);
  const fetchText = async (url) => {
    if (answers.has(url)) return answers.get(url);
    const known = Object.entries(STIX).find(([p]) => url.endsWith(p));
    if (known) return fixture(known[1]);
    if (url.endsWith(".stix2")) return JSON.stringify({ type: "bundle", id: "bundle--empty", objects: [] });
    throw new Error(`${url}: not in the fixtures`);
  };
  const rows = SOURCE_ROWS.map((r) => ({ ...r, min: 1 }));
  const keep = loadKeepList();
  const keepApps = loadKeepApps();
  const run = (extra = {}) => buildSet({ fetchText, keep, keepApps, now: new Date("2026-03-04T05:06:07Z"), seq: 2, privateKey: TEST_PRIVATE, publicKey: TEST_PUBLIC, requireSignature: true, rows, maxRejected: 0.3, log: () => {}, ...extra });
  /** The fixtures with one more Echap app added to ioc.yaml, as a tampered upstream commit would add it. */
  const withEchapApp = (yaml) => async (url) => (url === URLS.echapIoc ? `${fixture("echap-ioc.yaml").trimEnd()}\n${yaml}` : fetchText(url));

  test("the strict share of unusable entries stops a source whose lines are mostly junk", async () => {
    const strict = await run({ maxRejected: 0.05 });
    eq(failing(strict.results), ["unusable phishing"]);
  });

  test("builds, signs and passes every gate", async () => {
    const built = await run();
    eq(failing(built.results), []);
    eq(built.manifest.version, 2026030402);
    eq(built.manifest.built, "2026-03-04T05:06:07Z");
    eq(built.manifest.files.map((f) => f.name), ["apps-pkg.tkl", "apps-cert.tkl", "apps-sha.tkl", "hosts.tkl"]);
    eq(built.manifest.sources.map((s) => s.name), SOURCE_ROWS.map((s) => s.name));
    ok(built.manifest.sources.every((s) => s.entries > 0 && s.licence && s.url.startsWith("https://")));
    eq(signatureValid(built.set.manifestBytes, built.set.signature, TEST_PUBLIC), true);
    eq(built.results.some((r) => r.gate === "keep-list rescan"), true);
  });

  test("the lists hold what the sources said, labelled", async () => {
    const dir = mkdtempSync(path.join(tmpdir(), "defs-out-"));
    const built = await run();
    writeSet(dir, built.set, { publicKey: TEST_PUBLIC, keep });
    eq(lookupIn(dir, "package", "com.mxspy").found, "TheTruthSpy (stalkerware)");
    eq(lookupIn(dir, "package", "com.wisemo.host.v10").found, "WiseMo (watchware)");
    eq(lookupIn(dir, "sha", "2f3bc9ebe8c249f0416f5b0367f34b4b8f6aaa7d351dc5b4912fe2558491b6b7").found, "1TopSpy (stalkerware)");
    eq(lookupIn(dir, "package", parseStix(fixture("stix-cellebrite.json"), "c").pkg[0].text).found, "Cellebrite (forensic tool)");
    eq(lookupIn(dir, "package", "com.not.listed").found, null);
    const echapSha1 = parseEchapYaml(fixture("echap-ioc.yaml"), "stalkerware", "ioc.yaml").apps[0];
    eq(lookupIn(dir, "cert", echapSha1.sha1[0].toUpperCase()).found, `${echapSha1.name} (stalkerware)`, "an Echap SHA-1 certificate");
    eq(lookupIn(dir, "package", CANARY.package).found, CANARY.label);
    eq(lookupIn(dir, "host", CANARY.host).found, CANARY.host);
    const novi = parseStix(fixture("stix-novispy.json"), "n").cert[0].text;
    eq(lookupIn(dir, "cert", novi).found, "NoviSpy (spyware)");
    eq(lookupIn(dir, "host", "00000000000000000000000000000000000000000.xyz").found !== null, true);
    eq(lookupIn(dir, "host", "deep.sub.00000000000000000000000000000000000000000.xyz").found !== null, true, "parent walk");
    eq(lookupIn(dir, "host", "example-phish.com").found !== null, true, "upper case and trailing dot normalised");
    eq(lookupIn(dir, "host", "docs.google.com").found, null);
    eq(lookupIn(dir, "host", "79.docs.google.com").found, null, "dropped by the keep-list");
    eq(lookupIn(dir, "host", "bit.ly").found, null);
    eq(lookupIn(dir, "host", "blogspot.com").found, null);
    eq(lookupIn(dir, "host", "014oo.blogspot.com").found !== null, true, "a page on shared hosting is kept");
    eq(lookupIn(dir, "host", "x.westus.cloudapp.azure.com").found, null);
    eq(lookupIn(dir, "host", "accedss12-reflex44537.southcentralus.cloudapp.azure.com").found !== null, true);
    eq(lookupIn(dir, "host", "10.0.0.1").found, null);
    eq(lookupIn(dir, "package", "com.android.inputmethod.latinmy").found, "KidsShield (name used by stalkerware)", "a stalkerware name under a system prefix stays, said carefully");
    eq(failing(checkSet(readSet(dir), options({ keep }))), []);
    eq(loadVerifiedSet(dir, TEST_PUBLIC).manifest.version, 2026030402);
    rmSync(dir, { recursive: true, force: true });
  });

  test("a source that adds com.whatsapp: dropped, named, and the set does not have it", async () => {
    const lines = [];
    const built = await run({ fetchText: withEchapApp("- name: Added\n  type: stalkerware\n  packages:\n  - com.whatsapp\n  - com.added.spy\n"), log: (l) => lines.push(l) });
    eq(failing(built.results), []);
    const gate = built.results.find((r) => r.gate === "app keep-lists");
    ok(/package com\.whatsapp \(Added \(stalkerware\); from echap; keep com\.whatsapp, NEW\)/.test(gate.detail), gate.detail);
    const pkg = openTable(built.set.files.get("apps-pkg.tkl"), "apps-pkg.tkl");
    eq(lookupText(pkg, "com.whatsapp"), null);
    eq(lookupText(pkg, "com.added.spy"), "Added (stalkerware)", "the rest of the commit is used");
  });

  test("a source that adds the AOSP testkey, com.whatsapp and other protected names fails the build", async () => {
    const tampered = withEchapApp(
      "- name: Tampered\n  type: stalkerware\n  packages:\n  - com.whatsapp\n  - com.google.android.gms\n  - com.sec.android.app.launcher\n  certificates:\n" +
        "  - 61ED377E85D386A8DFEE6B864BD85B0BFAA5AF81\n  - C8A2E9BCCF597C2FB6DC66BEE293FC13F2FC47EC77BC6B2B0D52C11F51192AB8\n",
    );
    const built = await run({ fetchText: tampered });
    eq(failing(built.results), ["app keep-lists"]);
    const detail = built.results.find((r) => r.gate === "app keep-lists").detail;
    for (const named of ["com.whatsapp", "com.google.android.gms", "com.sec.android.app.launcher", "c8a2e9bccf597c2fb6dc66bee293fc13f2fc47ec77bc6b2b0d52c11f51192ab8", "61ed377e85d386a8dfee6b864bd85b0bfaa5af81"]) ok(detail.includes(named), `${named} is named`);
    ok(/4 new \(at most 3\)/.test(detail), detail);
    const cert = openTable(built.set.files.get("apps-cert.tkl"), "apps-cert.tkl");
    eq(lookupText(cert, "61ed377e85d386a8dfee6b864bd85b0bfaa5af81"), null, "the testkey never reaches the table");
    // Without the keep-lists the same input would have listed all of them: the gate is what stops it.
    const unprotected = await run({ fetchText: tampered, keepApps: NO_KEEP_APPS });
    eq(lookupText(openTable(unprotected.set.files.get("apps-pkg.tkl"), "p"), "com.whatsapp"), "Tampered (stalkerware)");
  });

  test("the same inputs give the same bytes", async () => {
    const a = await run();
    const b = await run();
    eq(a.set.manifestBytes.equals(b.set.manifestBytes), true);
    eq(a.set.signature, b.set.signature);
    eq([...a.set.files].every(([name, bytes]) => bytes.equals(b.set.files.get(name))), true);
  });

  test("a host table over its budget stops the build with the counts; nothing is cut", async () => {
    const full = await run();
    const wanted = openTable(full.set.files.get("hosts.tkl"), "hosts").entryCount;
    const exact = await run({ hostBudget: 16 + 8 * wanted });
    eq(failing(exact.results), [], "a budget that fits exactly");
    const small = await run({ hostBudget: 16 + 8 * 12 });
    ok(failing(small.results).includes("host budget"), failing(small.results).join());
    ok(/hosts for 11 places; over by/.test(small.results.find((r) => r.gate === "host budget").detail));
    eq(openTable(small.set.files.get("hosts.tkl"), "hosts").entryCount, wanted, "every host is still in the table it refuses to write");
    const parts = [{ id: "mvt", pkg: [], cert: [], sha: [], hosts: ["a.example", "b.example"], rejected: 0, raw: 2, notes: [] }, { id: "phishing", pkg: [], cert: [], sha: [], hosts: ["c.example", "d.example", "e.example"], rejected: 0, raw: 3, notes: [] }];
    const over = assemble(parts, { keep: new Map(), hostBudget: 16 + 8 * 4 });
    eq(over.budget.cap, 3, "one of the four places is the canary's");
    eq([over.budget.wanted, [...over.budget.over]], [5, [["phishing", 2]]]);
    eq(over.hosts.length, 5);
    eq(failing([hostBudgetGate(over.budget)]), ["host budget"]);
  });

  test("the shortest listed names are printed for a person to look at", async () => {
    const lines = [];
    await run({ log: (l) => lines.push(l) });
    const line = lines.find((l) => l.startsWith("the 50 listed hosts with the fewest labels: "));
    ok(line, "printed");
    eq(shortestHosts(["a.b.c", "x.y", "b.c", "1.2.3.4", "long.name"], 4), ["b.c", "x.y", "long.name", "a.b.c"], "fewest labels, then shortest");
  });

  test("a source that gives nothing stops the build", async () => {
    const empty = async (url) => (url === URLS.certPl ? "# nothing\n" : fetchText(url));
    await assert.rejects(run({ fetchText: empty }), /no hosts in the list/);
    const noHosts = async (url) => (url === URLS.certPl || url === URLS.phishing ? "not a host\n" : fetchText(url));
    const built = await run({ fetchText: noHosts, rows: SOURCE_ROWS.map((r) => ({ ...r, min: 1 })) });
    eq(built.ok, false);
    ok(failing(built.results).includes("source certpl") && failing(built.results).includes("unusable certpl"));
    checks++;
  });

  test("a failed download names the URL", async () => {
    const broken = async (url) => {
      if (url === URLS.phishing) throw new Error(`${url}: HTTP 500`);
      return fetchText(url);
    };
    await assert.rejects(run({ fetchText: broken }), /phishing-domains-ACTIVE\.txt: HTTP 500/);
    checks++;
  });

  test("a previous set: version must grow and a big drop is caught", async () => {
    const first = await run();
    const dir = mkdtempSync(path.join(tmpdir(), "defs-prev-"));
    writeSet(dir, first.set, { publicKey: TEST_PUBLIC, keep });
    const previous = loadVerifiedSet(dir, TEST_PUBLIC);
    eq((await run({ previous, seq: 3 })).ok, true);
    const same = await run({ previous, seq: 2 });
    eq(failing(same.results), ["version"]);
    const halved = async (url) => (url === URLS.phishing || url === URLS.certPl ? fixture("phishing-domains.txt").split("\n").slice(0, 8).join("\n") : fetchText(url));
    const dropped = await run({ previous, seq: 4, fetchText: halved });
    eq(failing(dropped.results), ["drop"]);
    eq((await run({ previous, seq: 4, fetchText: halved, allowDrop: true })).ok, true);
    writeFileSync(path.join(dir, "hosts.tkl"), Buffer.alloc(20));
    fails(() => loadVerifiedSet(dir, TEST_PUBLIC), /does not verify/);
    rmSync(dir, { recursive: true, force: true });
  });

  test("an unsigned build is allowed only when no signature is required", async () => {
    const unsigned = await run({ privateKey: null, requireSignature: false });
    eq([unsigned.ok, unsigned.set.signature], [true, null]);
    eq((await run({ privateKey: null, requireSignature: true })).ok, false);
    eq((await run({ privateKey: OTHER_PRIVATE })).ok, false, "a key that is not the one behind the public key");
  });

  test("writeSet leaves a folder that verifies and removes stale lists", async () => {
    const dir = mkdtempSync(path.join(tmpdir(), "defs-write-"));
    writeFileSync(path.join(dir, "old.tkl"), "x");
    const built = await run();
    writeSet(dir, built.set, { publicKey: TEST_PUBLIC, keep });
    eq(existsSync(path.join(dir, "old.tkl")), false);
    eq(failing(checkSet(readSet(dir), options({ keep }))), []);
    rmSync(dir, { recursive: true, force: true });
  });
});

// ---- the published set -------------------------------------------------------------------------------------------------

describe("published set", () => {
  const BASE = "https://example.github.io/toolkit-definitions/v1/";
  /** A fetcher that serves a set from memory under BASE; `serve(name)` may return bytes, a status number, or undefined for 404. */
  const serving = (set, tamper = {}) => {
    const files = new Map([...set.files, ["manifest.json", set.manifestBytes], ["manifest.json.sig", Buffer.from(set.signature)]]);
    const bytes = async (url) => {
      const name = url.slice(BASE.length);
      const body = tamper[name] ?? files.get(name);
      if (!body) throw Object.assign(new Error(`${url}: HTTP 404`), { status: 404 });
      return body;
    };
    return { bytes };
  };
  const dir = () => mkdtempSync(path.join(tmpdir(), "defs-pub-"));

  test("downloads and verifies what is published", async () => {
    const out = dir();
    const manifest = await fetchPublished({ base: BASE, dir: out, fetcher: serving(makeSet()), publicKey: TEST_PUBLIC });
    eq(manifest.version, 2026010101);
    eq(failing(checkSet(readSet(out), options())), []);
    rmSync(out, { recursive: true, force: true });
  });

  test("nothing published yet is not an error", async () => {
    eq(await fetchPublished({ base: BASE, dir: dir(), fetcher: { bytes: async (u) => { throw Object.assign(new Error(`${u}: HTTP 404`), { status: 404 }); } }, publicKey: TEST_PUBLIC }), null);
  });

  test("any other failure, a changed file or a wrong signature stops the job", async () => {
    const out = dir();
    await assert.rejects(fetchPublished({ base: BASE, dir: out, fetcher: { bytes: async (u) => { throw Object.assign(new Error(`${u}: HTTP 403`), { status: 403 }); } }, publicKey: TEST_PUBLIC }), /HTTP 403/);
    await assert.rejects(fetchPublished({ base: BASE, dir: out, fetcher: serving(makeSet(), { "hosts.tkl": Buffer.alloc(40) }), publicKey: TEST_PUBLIC }), /does not verify/);
    await assert.rejects(fetchPublished({ base: BASE, dir: out, fetcher: serving(makeSet({ key: OTHER_PRIVATE })), publicKey: TEST_PUBLIC }), /signature/);
    const evil = makeSet();
    const m = JSON.parse(evil.manifestBytes.toString());
    m.files[0].name = "../apps-pkg.tkl";
    const bad = Buffer.from(JSON.stringify(m));
    await assert.rejects(fetchPublished({ base: BASE, dir: out, fetcher: serving(evil, { "manifest.json": bad }), publicKey: TEST_PUBLIC }), /plain \.tkl name/);
    checks += 4;
    rmSync(out, { recursive: true, force: true });
  });

  test("a set of ours in the first format (6-byte host keys) is reported as such, not as a previous set", async () => {
    // What is online before this format: hosts.tkl with 6-byte keys, and a manifest whose counts only fit those.
    const key6 = (text) => keyOf(text).subarray(0, 6);
    const hostsText = [CANARY.host, ...TINY.hosts].sort((a, b) => Buffer.compare(key6(a), key6(b)));
    const hosts6 = Buffer.concat([Buffer.from("TKL1", "latin1"), Buffer.from([6, 0, 0, 0]), Buffer.from([0, 0, 0, hostsText.length, 0, 0, 0, 0]), ...hostsText.map(key6)]);
    const old = makeSet();
    old.files.set("hosts.tkl", hosts6);
    const m = JSON.parse(old.manifestBytes.toString());
    Object.assign(m.files.find((f) => f.name === "hosts.tkl"), { sha256: sha256Hex(hosts6), bytes: hosts6.length, entries: hostsText.length });
    old.manifestBytes = Buffer.from(`${JSON.stringify(m, null, 2)}\n`);
    old.signature = signBytes(old.manifestBytes, TEST_PRIVATE);
    const out = dir();
    const answer = await fetchPublished({ base: BASE, dir: out, fetcher: serving(old), publicKey: [TEST_PUBLIC] });
    ok(answer instanceof OlderFormat, String(answer));
    ok(/6-byte keys/.test(answer.reason), answer.reason);
    // Signed by someone else, the same files are an error, never an "older format".
    old.signature = signBytes(old.manifestBytes, OTHER_PRIVATE);
    await assert.rejects(fetchPublished({ base: BASE, dir: out, fetcher: serving(old), publicKey: TEST_PUBLIC }), /cannot fit/);
    checks++;
    rmSync(out, { recursive: true, force: true });
  });
});

// ---- the command line, the version, the copies -------------------------------------------------------------------------------

describe("small things", () => {
  test("versions are yyyymmddNN", () => {
    eq(versionFor(new Date("2026-11-12T23:59:59Z"), 1), 2026111201);
    eq(versionFor(new Date("2026-01-02T00:00:00Z"), 12), 2026010212);
    fails(() => versionFor(new Date(), 0), /1 to 99/);
    fails(() => versionFor(new Date(), 100), /1 to 99/);
  });

  test("a build date may be today or earlier, never later", () => {
    const now = new Date("2026-11-12T06:07:08Z");
    eq(buildDate("20261112", now).toISOString(), "2026-11-12T06:07:08.000Z");
    eq(buildDate("20261001", now).toISOString(), "2026-10-01T06:07:08.000Z");
    fails(() => buildDate("20261113", now), /in the future/);
    fails(() => buildDate("20991231", now), /in the future/);
    fails(() => buildDate("20260230", now), /not a real day/);
    fails(() => buildDate("2026-11-12", now), /yyyymmdd/);
    const run = spawnSync(process.execPath, [path.join(HERE, "threat-data.mjs"), "build", "--out", path.join(tmpdir(), "never-written"), "--date", "20991231"], { encoding: "utf8" });
    eq(run.status, 1);
    ok(/in the future/.test(run.stderr), run.stderr);
  });

  test("arguments", () => {
    eq(parseCommandLine(["build", "--out", "d", "--seq", "auto", "--allow-drop"]).flags.out, "d");
    eq(parseCommandLine(["build", "--out", "d"]).flags.seq, "01");
    eq(parseCommandLine(["build", "--out", "d", "--allow-drop"]).flags["allow-drop"], true);
    eq(parseCommandLine(["build", "--out", "d", "--allow-growth"]).flags["allow-growth"], true);
    eq(parseCommandLine(["lookup", "d", "host", "a.b"]).args, ["d", "host", "a.b"]);
    fails(() => parseCommandLine(["build", "--nope"]), /nope/);
  });

  test("the copy in definitions-site is current", { skip: !existsSync(path.join(HERE, "..", "definitions-site")) && "no definitions-site folder in this repository" }, () => {
    for (const [from, to] of siteCopies()) {
      ok(existsSync(to), `${path.relative(HERE, to)} is missing; run: node scripts/threat-data.mjs sync-site`);
      eq(readFileSync(from).equals(readFileSync(to)), true, `${path.relative(HERE, to)} differs; run: node scripts/threat-data.mjs sync-site`);
    }
  });

  test("the set bundled in the app verifies against the real public key", { skip: !existsSync(path.join(HERE, "..", "app/src/main/assets/threat/manifest.json")) && "no bundled set in this repository" }, () => {
    const results = checkSet(readSet(path.join(HERE, "..", "app/src/main/assets/threat")), { publicKey: publicKeys(), keep: loadKeepList(), requireSignature: true });
    eq(failing(results), []);
  });

  test("the published manifest never names a file the app does not know", () => {
    eq(FILES.map((f) => f.name), ["apps-pkg.tkl", "apps-cert.tkl", "apps-sha.tkl", "hosts.tkl"]);
    eq(SOURCE_ROWS.every((r) => /^https:\/\//.test(r.url) && r.licence && r.min > 0), true);
  });
});

// Registered last, so it runs last.
test("report", () => {
  ok(checks > 300, "the checks did not run");
  console.log(`threat-data: ${checks} checks ran`);
});
