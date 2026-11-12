// Ed25519 signing of manifest.json. The signature is the base64 of the signature over the exact
// bytes of the file. The private key is read from TOOLKIT_DEFS_KEY_FILE (a PEM file) or
// TOOLKIT_DEFS_KEY (PEM text) and is never printed or logged.

import { createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { readFileSync } from "node:fs";

/**
 * Same values as DefsFormat.PUBLIC_KEYS: 32 raw bytes each, base64. A test compares the two files.
 * The first signs every set today; the second is a backup whose private half is kept offline by the
 * owner, so the first can be replaced if it ever leaks (see DefsFormat). A set is valid when ANY of
 * these signs it.
 */
export const PUBLIC_KEYS = Object.freeze(["kTIP0679KOLMbi09sug9uK9DCfoZNQAv99z1/enH91s=", "AFb41ClemNe2AVb//8tbV9qLX3kx+WowNNv9uIFCVHY="]);

/** The key the daily build signs with today. */
export const PUBLIC_KEY = PUBLIC_KEYS[0];

/** A public key object from the raw 32 bytes in base64. */
export function publicKeyFrom(base64) {
  const raw = Buffer.from(base64, "base64");
  if (raw.length !== 32) throw new Error(`an Ed25519 public key is 32 bytes, this one is ${raw.length}`);
  return createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: raw.toString("base64url") }, format: "jwk" });
}

/**
 * The signing key from the environment, or null when neither variable is set.
 * Errors never include the key text.
 */
export function privateKeyFromEnv(env = process.env) {
  let pem = null;
  if (env.TOOLKIT_DEFS_KEY_FILE) {
    try {
      pem = readFileSync(env.TOOLKIT_DEFS_KEY_FILE, "utf8");
    } catch (error) {
      throw new Error(`TOOLKIT_DEFS_KEY_FILE ${env.TOOLKIT_DEFS_KEY_FILE} cannot be read (${error.code ?? "error"})`);
    }
  } else if (env.TOOLKIT_DEFS_KEY) {
    pem = env.TOOLKIT_DEFS_KEY;
    // A secret pasted on one line carries "\n" as two characters.
    if (!pem.includes("\n")) pem = pem.replace(/\\n/g, "\n");
  }
  if (pem === null) return null;
  try {
    const key = createPrivateKey(pem);
    if (key.asymmetricKeyType !== "ed25519") throw new Error("not an Ed25519 key");
    return key;
  } catch {
    throw new Error("the signing key is not a readable Ed25519 private key in PEM form");
  }
}

/** Base64 signature over the bytes. */
export const signBytes = (bytes, privateKey) => sign(null, bytes, privateKey).toString("base64");

/** True when the base64 signature is valid for the bytes under the public key. */
export function signatureValid(bytes, signatureText, publicKey) {
  const text = signatureText.trim();
  if (!/^[A-Za-z0-9+/]{86}==$/.test(text)) return false;
  return verify(null, bytes, publicKey, Buffer.from(text, "base64"));
}

/** Index of the first key in `publicKeys` the signature is valid for, or -1. */
export const signedByAny = (bytes, signatureText, publicKeys) => publicKeys.findIndex((key) => signatureValid(bytes, signatureText, key));

/** Every key of PUBLIC_KEYS as a key object. */
export const publicKeys = () => PUBLIC_KEYS.map(publicKeyFrom);
