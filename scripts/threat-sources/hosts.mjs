// Host names for the web list: normalising, the parent-name walk the app uses, and the keep-list
// that stops a bad upstream list from making the app warn on a major site.

import { readFileSync } from "node:fs";
import { domainToASCII } from "node:url";
import path from "node:path";
import { keyOf } from "./tkl.mjs";

const LABEL = /^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?$/;
const TLD = /^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/;
const IPV4 = /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;

/** False for addresses that are never a phishing site: this network, private, loopback, link-local, shared, multicast and reserved. */
function publicIpv4(text) {
  const [a, b] = text.split(".").map(Number);
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  return true;
}

/**
 * Characters whose UTS-46 mapping depends on the processing mode: transitional processing (IDNA 2003,
 * java.net.IDN, old browsers) maps ß to "ss" and ς to σ and drops the joiners; nontransitional keeps
 * them. The app (tools/qr/IcuIdna.kt) is nontransitional, and so is Node's domainToASCII (WHATWG URL),
 * so a name with one of them is stored in that form. The transitional form ("fass.de" for "faß.de") is
 * another domain that someone else may own, so it is never added.
 */
const MODE_DEPENDENT = /[ßς‌‍]/u;

/**
 * The host in the form the lists store, and how it got there.
 * `host` is lower-case ASCII, punycode for other scripts, no trailing dot, or null when the text is not
 * a usable host: a path, port, query, wildcard or space in it (so never an IPv6 literal), an empty or
 * oversize label, a single label, a last label that is not a real top-level name, or a name that
 * UTS-46 refuses. A public dotted-quad IPv4 address is kept as written.
 * `idna` is null for ASCII input, "nontransitional" when the name has a mode-dependent character
 * (see MODE_DEPENDENT), else "converted".
 * @returns {{ host: string | null, idna: null | "converted" | "nontransitional" }}
 */
export function readHost(raw) {
  const none = { host: null, idna: null };
  if (typeof raw !== "string") return none;
  let host = raw.trim().toLowerCase();
  if (host.endsWith(".")) host = host.slice(0, -1);
  if (host.length === 0 || /[\s/\\:?#@*%!'"<>()[\]{},;=&+$^|~`]/.test(host)) return none;
  let idna = null;
  if (/[^\x00-\x7f]/.test(host)) {
    idna = MODE_DEPENDENT.test(host) ? "nontransitional" : "converted";
    host = domainToASCII(host);
    if (host === "") return none;
  }
  if (host.length > 253) return none;
  if (IPV4.test(host)) return publicIpv4(host) ? { host, idna } : none;
  const labels = host.split(".");
  if (labels.length < 2) return none;
  for (const label of labels) {
    if (label.length === 0 || label.length > 63 || !LABEL.test(label)) return none;
  }
  if (!TLD.test(labels[labels.length - 1])) return none;
  return { host, idna };
}

/** The host in the form the lists store, or null (see readHost). */
export const normaliseHost = (raw) => readHost(raw).host;

/**
 * The host itself, then each parent name down to two labels: "a.b.evil.net" gives a.b.evil.net,
 * b.evil.net, evil.net. A name whose last label is all digits (an IPv4 address) is tried only whole:
 * an address has no parents. The app's HostNames.candidates follows the same rule.
 */
export function hostWalk(host) {
  if (/(^|\.)[0-9]+$/.test(host)) return [host];
  const labels = host.split(".");
  const out = [];
  for (let i = 0; i <= labels.length - 2; i++) out.push(labels.slice(i).join("."));
  return out;
}

export const KEEP_FILE = path.join(import.meta.dirname, "keep-hosts.txt");

/**
 * Parse the keep-list text. One host per line; "#" starts a comment. A line "host shared" marks a
 * shared-hosting or registry domain: the name itself is never listed, but hosts below it may be.
 * @returns {Map<string, boolean>} host to "shared"
 */
export function parseKeepList(text, label = "keep-list") {
  const keep = new Map();
  text.split(/\r?\n/).forEach((line, i) => {
    const content = line.replace(/#.*/, "").trim();
    if (!content) return;
    const [rawHost, flag, ...rest] = content.split(/\s+/);
    const host = normaliseHost(rawHost);
    if (!host || host !== rawHost || rest.length > 0 || (flag !== undefined && flag !== "shared")) {
      throw new Error(`${label} line ${i + 1}: "${content}" is not "host" or "host shared"`);
    }
    if (keep.has(host)) throw new Error(`${label} line ${i + 1}: ${host} is listed twice`);
    keep.set(host, flag === "shared");
  });
  return keep;
}

export const loadKeepList = (file = KEEP_FILE) => parseKeepList(readFileSync(file, "utf8"), path.basename(file));

/**
 * What the keep-list protects. A bad-host entry is refused when it is a kept host or a parent of
 * one (so a lookup that walks up from a kept host never hits), lies below a kept host that is not a
 * shared domain, or has the same 8-byte key as a protected name (a hash collision would warn on a
 * major site just the same).
 */
export function buildKeeper(keep, keyFor = (host) => keyOf(host).toString("hex")) {
  const names = new Set();
  for (const host of keep.keys()) for (const name of hostWalk(host)) names.add(name);
  const keys = new Map([...names].map((name) => [keyFor(name), name]));
  return {
    keep,
    /** Null when the host may be listed, else { kind: "kept" | "below" | "clash", name } with the kept host concerned. */
    reason(host) {
      if (names.has(host)) return { kind: "kept", name: host };
      // The nearest kept name above the host decides: below a shared domain the host may be listed.
      for (const name of hostWalk(host)) {
        if (name === host || !keep.has(name)) continue;
        if (keep.get(name) === false) return { kind: "below", name };
        break;
      }
      const clash = keys.get(keyFor(host));
      return clash ? { kind: "clash", name: clash } : null;
    },
  };
}

/**
 * Drop what the keep-list protects.
 * @returns {{ kept: string[], dropped: Map<string, number> }} dropped counts by "kind name"
 */
export function applyKeepList(hosts, keeper) {
  const kept = [];
  const dropped = new Map();
  for (const host of hosts) {
    const reason = keeper.reason(host);
    if (reason === null) kept.push(host);
    else {
      const why = `${reason.kind} ${reason.name}`;
      dropped.set(why, (dropped.get(why) ?? 0) + 1);
    }
  }
  return { kept, dropped };
}
