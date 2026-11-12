# Toolkit definitions

Signed lists of known threats for the Toolkit app: stalkerware and spyware apps, and web hosts used for phishing. The files are rebuilt every day from open sources and published as plain static files with GitHub Pages.

This repository holds no user data. It has no server and no code that runs for a visitor. Downloading a file is an ordinary web request to GitHub Pages.

Published at `https://miniwhale-git.github.io/toolkit-definitions/v1/`

| File | What it is |
| --- | --- |
| `manifest.json` | Version (`yyyymmddNN`), build time, the list files with their SHA-256, size and entry count, and the sources with their licences. |
| `manifest.json.sig` | Base64 Ed25519 signature over the exact bytes of `manifest.json`. |
| `apps-pkg.tkl` | Android package names, each with a label such as `mSpy (stalkerware)`. |
| `apps-cert.tkl` | SHA-256 or SHA-1 fingerprints of signing certificates, with labels. |
| `apps-sha.tkl` | SHA-256 hashes of APK files, with labels. |
| `hosts.tkl` | Host names used for phishing or spyware command servers. No labels. |

A `.tkl` file is a sorted table of short hashed keys (the first 6 or 8 bytes of SHA-256 over the item's text), searched by binary search. The lists do not contain the names and hashes in readable form, only these keys and the labels. A key match is a hint, not proof: the app shows it as a warning, never as a verdict.

The signature is checked with this public key (Ed25519, 32 bytes, base64):

```
kTIP0679KOLMbi09sug9uK9DCfoZNQAv99z1/enH91s=
```

## Check a download

```
node scripts/threat-data.mjs verify DIR
node scripts/threat-data.mjs lookup DIR package com.example.app
node scripts/threat-data.mjs lookup DIR host login.example.net
```

`verify` checks the signature, every hash, the sort order, the canaries and the sizes. A certificate can be looked up by its SHA-256 or its SHA-1 (`lookup DIR cert HEX`). `lookup` answers one question the way the app does; a host is also looked up by each parent name down to two labels. Node 22 or later, no packages to install.

## Sources

| Source | Licence | What is taken |
| --- | --- | --- |
| [Echap stalkerware-indicators](https://github.com/AssoEchap/stalkerware-indicators) | CC-BY-4.0 | package names, APK hashes, signing certificate fingerprints (SHA-1) (labels name the app) |
| [Mobile Verification Toolkit indicators](https://github.com/mvt-project/mvt-indicators) | MIT | package names, certificate and APK hashes, domains of spyware campaigns |
| [Amnesty International Security Lab indicators](https://github.com/AmnestyTech/investigations) | CC-BY-2.0 | the same, for the campaigns Amnesty published |
| [Phishing.Database](https://github.com/Phishing-Database/Phishing.Database) | MIT | active phishing domains |
| [CERT Polska warning list](https://cert.pl/en/warning-list/) | free for any use, including commercial | domains |

Credit and licence notices are in [NOTICE.md](NOTICE.md). The MVT index is followed only for repositories whose licence was read (MVT's own and Amnesty Tech's); anything else it lists is skipped.

Left out on purpose:

- URLhaus (abuse.ch): its terms do not allow this use.
- Leaked device-maker signing keys (the 2022 Android Partner Vulnerability Initiative report): the full list of certificate fingerprints could not be cited from a public page, so none are included. One value is quoted in the press, and it belongs to certificates that real system apps still carry, so a single entry would only cause false alarms.

## What protects against bad data

Every build runs checks and publishes nothing if one fails, so the last good set stays online:

- each source must give at least about half of what it gave when the checks were set, and may not have more than 5% unusable lines;
- the set may not be more than 30% smaller than the one online, its app entries may not grow by more than 25%, and its version must be higher; every certificate entry the online set did not have is printed in the build log;
- a **host keep-list** (`scripts/threat-sources/keep-hosts.txt`, over 2,000 hosts) of major global and Indian sites, banks, government and payment domains is removed from the host list, together with everything below them, so a poisoned or careless upstream list cannot make the app warn on `google.com` or `sbi.co.in`. Shared hosting and user content (`blogspot.com`, `github.io`, `web.app`, `pages.dev`, paste sites, cloud storage such as `firebasestorage.googleapis.com`, form hosts, link shorteners) is marked `shared`: the name itself is never listed, a deeper name can be;
- **app keep-lists**: `keep-packages.txt` (over 400 of the most installed apps, and everything under `android.`, `com.android.` and `com.google.android.` except stalkerware names that imitate them, which stay listed as "name used by stalkerware") and `keep-certs.txt` (the public AOSP test certificates, computed from the files in the Android source tree). An entry that hits them is dropped and printed; more than 3 new hits in one run stop the build, since that looks like a tampered source;
- labels are built from the source's app name through a strict filter (letters, digits, space, dot, hyphen, underscore; at most 30 characters; no long number, no web address); anything else becomes "Stalkerware", "Monitoring app" or "Spyware";
- tables must be sorted with no repeated key, keys are 8 bytes everywhere, sizes must stay within the app's limits (host table 6 MB; the build stops rather than cut it), every table must answer its canary entry (the app refuses a set that does not), and the manifest, hashes and signature must verify under the same rules the app reads them by. A `--date` in the future is refused.

If the app warns about a site that is fine, write to support@attnom.com with the host name. It goes on the keep-list.

## How it runs

`.github/workflows/publish-lists.yml` runs every day at 01:23 UTC and on demand:

1. runs the tests;
2. downloads the set that is online now and verifies it;
3. builds a new set from the sources, compares it with the old one, signs it with the secret `TOOLKIT_DEFS_KEY` of the `publish` environment, which only the main branch may use;
4. verifies the result and deploys `v1/` to GitHub Pages.

When a build fails, nothing is published, and the job "report" opens the issue "Daily lists failed" (or adds to it while it is open) with the failing gate. The keep-alive commit runs either way, so failing builds never let GitHub switch the schedule off.

Run by hand with **Actions > publish > Run workflow**. The option "allow_drop" accepts a set that is more than 30% smaller, for when a source really shrank; "allow_growth" accepts app entries more than 25% up.

The scripts in `scripts/` are a copy of the ones in the Toolkit repository. Change them there.

## Contact

support@attnom.com
