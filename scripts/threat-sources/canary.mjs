// One known entry in every table (DefsCanary in the app). The app refuses a set whose tables do not
// answer these, so a set that loads but answers nothing (keys hashed the wrong way, a table cut short)
// is never used. None can match a real app, file or site: Android does not allow "-" in a package
// name, nothing hashes to all zeros, and .invalid never resolves.
//
// The manifest's `entries` counts every entry in the table, the canary included (the app compares it
// with the table's own count); the app leaves the canary out of the numbers it shows.

export const CANARY = Object.freeze({
  package: "toolkit.canary-check",
  hex: "0".repeat(64),
  host: "canary.toolkit.invalid",
  label: "Toolkit list check",
});

/** The canary item for each table kind, as table entries. */
export const canaryEntry = (kind) => {
  if (kind === "pkg") return { text: CANARY.package, label: CANARY.label };
  if (kind === "cert" || kind === "sha") return { text: CANARY.hex, label: CANARY.label };
  if (kind === "hosts") return { text: CANARY.host };
  throw new Error(`no canary for table kind "${kind}"`);
};

/** The entries with the canary first (the first item given for a key keeps its label). */
export const withCanary = (kind, entries) => [canaryEntry(kind), ...entries];
