// Where the data comes from: one place for URLs, licences, size caps and the least each source must give.
//
// Licences were read from each project's own README or LICENSE file on 2026-11-12:
//   Echap          README: "licensed under CC-BY" (creativecommons.org/licenses/by/4.0)
//   MVT            LICENSE file: MIT (the repository and the community files in it)
//   Amnesty Tech   README: "shared under the license CC-BY" (creativecommons.org/licenses/by/2.0)
//   Phishing.Database  LICENSE file: MIT
//   CERT Polska    cert.pl/en/warning-list "Data usage policy": free for any purpose, including commercial
// Skipped: URLhaus (abuse.ch terms), and the leaked maker signing keys (no public list of every value
// could be cited; see the README of definitions-site).

const RAW = "https://raw.githubusercontent.com";

export const URLS = {
  echapIoc: `${RAW}/AssoEchap/stalkerware-indicators/master/ioc.yaml`,
  echapWatchware: `${RAW}/AssoEchap/stalkerware-indicators/master/watchware.yaml`,
  echapSamples: `${RAW}/AssoEchap/stalkerware-indicators/master/samples.csv`,
  mvtIndex: `${RAW}/mvt-project/mvt-indicators/main/indicators.yaml`,
  phishing: `${RAW}/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt`,
  certPl: "https://hole.cert.pl/domains/v2/domains.txt",
};

/** Largest download accepted, in bytes. */
export const MAX_BYTES = { yaml: 4 * 1024 * 1024, csv: 4 * 1024 * 1024, index: 256 * 1024, stix: 8 * 1024 * 1024, hostList: 40 * 1024 * 1024 };
/** Largest total of STIX files followed from the MVT index. */
export const MAX_STIX_TOTAL = 40 * 1024 * 1024;

/**
 * The rows of the manifest's `sources`, in the order they are listed. `min` is the fewest entries
 * (all tables together) the source may give before the build stops: about half of what it gave on
 * 2026-11-12.
 */
export const SOURCE_ROWS = [
  { id: "echap", name: "Echap stalkerware-indicators", licence: "CC-BY-4.0", url: "https://github.com/AssoEchap/stalkerware-indicators", min: 1900 },
  { id: "mvt", name: "Mobile Verification Toolkit indicators", licence: "MIT", url: "https://github.com/mvt-project/mvt-indicators", min: 700 },
  { id: "amnesty", name: "Amnesty International Security Lab indicators", licence: "CC-BY-2.0", url: "https://github.com/AmnestyTech/investigations", min: 1900 },
  { id: "phishing", name: "Phishing.Database (active domains)", licence: "MIT", url: "https://github.com/Phishing-Database/Phishing.Database", min: 195000 },
  { id: "certpl", name: "CERT Polska warning list", licence: "Free use (CERT Polska data policy)", url: "https://cert.pl/en/warning-list/", min: 62000 },
];

/** Who fills the host table first when it is over budget. The first has the most claim on the space. */
export const HOST_PRIORITY = ["mvt", "amnesty", "certpl", "phishing"];

/** Repositories whose age is reported (a warning only): path of the main file and the age that is too old, in days. */
export const FRESHNESS = [
  { label: "Echap ioc.yaml", owner: "AssoEchap", repo: "stalkerware-indicators", path: "ioc.yaml", maxDays: 180 },
  { label: "MVT indicators.yaml", owner: "mvt-project", repo: "mvt-indicators", path: "indicators.yaml", maxDays: 365 },
  { label: "Phishing.Database domains", owner: "Phishing-Database", repo: "Phishing.Database", path: "phishing-domains-ACTIVE.txt", maxDays: 14 },
];

/** A gate stops the build when a source rejects more than this share of its entries as unusable. */
export const MAX_REJECTED_SHARE = 0.05;
/** A gate stops the build when a file shrinks by more than this against the previous set. */
export const MAX_DROP = 0.3;
/** A gate stops the build when the app entries together grow by more than this against the previous set. */
export const MAX_GROWTH = 0.25;
