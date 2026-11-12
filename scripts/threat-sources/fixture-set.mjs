// A tiny set with fixed content, for proving a signing key: `threat-data.mjs sign-fixture` signs it with
// the key in the environment. fixtures/backup-key-set is this set signed once with the offline backup key,
// so tests on both sides can check that key's private half matches the second of DefsFormat.PUBLIC_KEYS.

import { withCanary } from "./canary.mjs";
import { manifestBytes } from "./manifest.mjs";
import { writeTable } from "./tkl.mjs";

export const FIXTURE_VERSION = 2026111201;
export const FIXTURE_BUILT = new Date("2026-11-12T00:00:00Z");

/** The fixed entries: one per table besides the canaries. */
export const FIXTURE_ENTRIES = Object.freeze({
  pkg: [{ text: "com.example.backupkey", label: "Backup key check (stalkerware)" }],
  cert: [{ text: "b".repeat(64), label: "Backup key check (spyware)" }],
  sha: [{ text: "c".repeat(64), label: "Backup key check (watchware)" }],
  hosts: ["backup-key.example"],
});

/** The unsigned set: { manifestBytes, files }. The same bytes on every run. */
export function fixtureSet() {
  const tables = [
    ["apps-pkg.tkl", writeTable({ labelled: true, entries: withCanary("pkg", FIXTURE_ENTRIES.pkg) })],
    ["apps-cert.tkl", writeTable({ labelled: true, entries: withCanary("cert", FIXTURE_ENTRIES.cert) })],
    ["apps-sha.tkl", writeTable({ labelled: true, entries: withCanary("sha", FIXTURE_ENTRIES.sha) })],
    ["hosts.tkl", writeTable({ labelled: false, entries: withCanary("hosts", FIXTURE_ENTRIES.hosts.map((text) => ({ text }))) })],
  ];
  const files = tables.map(([name, t]) => ({ name, bytes: t.bytes, entries: t.entries }));
  const bytes = manifestBytes({
    version: FIXTURE_VERSION,
    built: FIXTURE_BUILT,
    files,
    sources: [{ name: "Toolkit key check", licence: "CC0-1.0", url: "https://github.com/miniwhale-git/toolkit-definitions", entries: 4 }],
  });
  return { manifestBytes: bytes, files: new Map(files.map((f) => [f.name, f.bytes])) };
}
