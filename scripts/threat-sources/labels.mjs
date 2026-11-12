// What the user is shown for a listed app. The name comes from a source, so a compromised source
// could name a "threat" "Call +1 555 0100 to remove". A name is used only when it passes a strict
// filter; anything else becomes the plain word for its kind. The app applies the same rule when it
// shows a label (LabelText.shown in DefsFormat's package), so what is stored is what is shown.
//
// A label is NAME or "NAME (KIND)". NAME: ASCII letters, digits, space, dot, hyphen and underscore
// only, at most 30 characters, at least one letter, no run of 5 or more digits, no "http" or "www".
// KIND: one of the words in KINDS.

export const NAME_MAX = 30;

/** Each kind and the generic label used when a name does not pass. */
export const KINDS = Object.freeze({
  stalkerware: "Stalkerware",
  watchware: "Monitoring app",
  spyware: "Spyware",
  "forensic tool": "Forensic tool",
  "name used by stalkerware": "Name used by stalkerware",
  "name used by watchware": "Name used by a monitoring app",
  "name used by spyware": "Name used by spyware",
});

/** The name when it passes the filter, else null. */
export function safeName(raw) {
  if (typeof raw !== "string") return null;
  const name = raw.trim();
  if (name.length === 0 || name.length > NAME_MAX) return null;
  if (!/^[A-Za-z0-9 ._-]+$/.test(name)) return null;
  if (/[0-9]{5}/.test(name)) return null;
  if (/http|www/i.test(name)) return null;
  if (!/[A-Za-z]/.test(name)) return null;
  return name;
}

/** "Name (kind)" when the name passes, else the generic label for the kind. */
export function threatLabel(name, kind) {
  if (!(kind in KINDS)) throw new Error(`unknown kind "${kind}"`);
  const safe = safeName(name);
  return safe === null ? KINDS[kind] : `${safe} (${kind})`;
}

const SUFFIX = new RegExp(`^(.*) \\((${Object.keys(KINDS).join("|")})\\)$`);

/** Splits "Name (kind)" into its parts; kind is null when the label has no known kind. */
export function splitLabel(label) {
  const m = SUFFIX.exec(label);
  return m ? { name: m[1], kind: m[2] } : { name: label, kind: null };
}

/** True when the app shows this label as it is (LabelText.shown leaves it alone). */
export function labelAllowed(label) {
  const { name } = splitLabel(label);
  return safeName(name) === name;
}

/**
 * The label for an app whose package name imitates a system one ("com.android.core.mngi"): it names
 * the threat but says the name is used by it, because a phone maker could ship the same name.
 */
export function nameUsedLabel(label) {
  const { name, kind } = splitLabel(label);
  const generic = Object.entries(KINDS).find(([, g]) => g === label)?.[0];
  const base = kind ?? generic ?? "stalkerware";
  const used = base.startsWith("name used by ") ? base : `name used by ${base === "forensic tool" ? "spyware" : base}`;
  return kind === null ? KINDS[used] : threatLabel(name, used);
}
