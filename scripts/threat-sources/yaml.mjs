// A strict reader for the small part of YAML the Echap indicator files use: block lists, block
// mappings (also "- key: value" list items), plain and quoted scalars, and "#" comments.
// Everything else (flow lists and maps, anchors, tags, block scalars, tabs, multi-line scalars,
// duplicate keys, documents markers) stops with the line number, so a change of shape in the
// upstream file fails the build instead of reading wrong. Scalars stay strings: nothing becomes
// a number, a boolean or null on its own. A key with no value is null.

export class YamlError extends Error {}

/**
 * @param {string} text
 * @param {string} [label] file name for messages
 * @returns {null | string | Array | Record<string, unknown>} maps have a null prototype
 */
export function parseYaml(text, label = "yaml") {
  const lines = [];
  text.split(/\r?\n/).forEach((raw, i) => {
    const no = i + 1;
    if (/^\s*(#.*)?$/.test(raw)) return;
    const indent = raw.length - raw.trimStart().length;
    if (/\t/.test(raw.slice(0, indent))) throw new YamlError(`${label} line ${no}: a tab in the indentation`);
    const body = raw.slice(indent);
    if (body === "---" || body === "...") throw new YamlError(`${label} line ${no}: document markers are not supported`);
    lines.push({ no, indent, text: body.trimEnd() });
  });
  let pos = 0;
  const fail = (line, why) => {
    throw new YamlError(`${label} line ${line.no}: ${why}`);
  };
  const isDash = (line) => line.text === "-" || line.text.startsWith("- ");

  function scalar(raw, line) {
    const value = raw.trim();
    if (value === "") return null;
    const first = value[0];
    if (first === "'" || first === '"') return quoted(value, line);
    if ("[{|>&*!%@`,?".includes(first)) fail(line, `"${first}" starts a value this reader does not support`);
    const noComment = value.replace(/\s+#.*$/, "");
    if (/:(\s|$)/.test(noComment)) fail(line, `"${noComment}" looks like a mapping where a value was expected`);
    return noComment;
  }

  function quoted(value, line) {
    const quote = value[0];
    let out = "";
    let i = 1;
    for (; i < value.length; i++) {
      const c = value[i];
      if (quote === "'") {
        if (c === "'") {
          if (value[i + 1] === "'") {
            out += "'";
            i++;
            continue;
          }
          break;
        }
        out += c;
      } else {
        if (c === '"') break;
        if (c === "\\") {
          const next = value[++i];
          const map = { '"': '"', "\\": "\\", "/": "/", n: "\n", t: "\t" };
          if (!(next in map)) fail(line, `unsupported escape \\${next ?? ""}`);
          out += map[next];
          continue;
        }
        out += c;
      }
    }
    if (i >= value.length) fail(line, "quoted value is not closed on its line");
    const rest = value.slice(i + 1).trim();
    if (rest !== "" && !rest.startsWith("#")) fail(line, "text after the closing quote");
    return out;
  }

  function block(indent) {
    const line = lines[pos];
    return isDash(line) ? sequence(indent) : mapping(indent);
  }

  function sequence(indent) {
    const items = [];
    while (pos < lines.length && lines[pos].indent === indent && isDash(lines[pos])) {
      const line = lines[pos];
      const rest = line.text.slice(1).trimStart();
      if (rest === "") {
        pos++;
        const next = lines[pos];
        items.push(next && next.indent > indent ? block(next.indent) : null);
      } else if (isMappingStart(rest)) {
        // "- key: value": the rest of the line is the first line of a mapping that sits two columns in
        line.indent = indent + (line.text.length - rest.length);
        line.text = rest;
        items.push(mapping(line.indent));
      } else if (isDash({ text: rest })) {
        fail(line, "a list inside a list item on one line is not supported");
      } else {
        pos++;
        items.push(scalar(rest, line));
      }
    }
    checkNotDeeper(indent);
    return items;
  }

  function isMappingStart(text) {
    const first = text[0];
    if (first === "'" || first === '"' || "[{|>&*!%@`,?".includes(first)) return false;
    return /:(\s|$)/.test(text);
  }

  function mapping(indent) {
    const map = Object.create(null);
    while (pos < lines.length && lines[pos].indent === indent && !isDash(lines[pos])) {
      const line = lines[pos];
      if (!isMappingStart(line.text)) fail(line, `expected "key: value", found "${line.text}"`);
      const match = line.text.match(/^(.*?)\s*:(?:\s+(.*))?$/);
      const key = match[1];
      if (key === "" || /[#'"]/.test(key)) fail(line, `unsupported key "${key}"`);
      if (key in map) fail(line, `key "${key}" appears twice`);
      pos++;
      const value = match[2] ?? "";
      if (value.trim() !== "" && !value.trim().startsWith("#")) {
        map[key] = scalar(value, line);
      } else {
        const next = lines[pos];
        if (next && next.indent > indent) map[key] = block(next.indent);
        else if (next && next.indent === indent && isDash(next)) map[key] = sequence(indent);
        else map[key] = null;
      }
    }
    checkNotDeeper(indent);
    return map;
  }

  function checkNotDeeper(indent) {
    const next = lines[pos];
    if (next && next.indent > indent) fail(next, "unexpected indentation");
  }

  if (lines.length === 0) return null;
  if (lines[0].indent !== 0) fail(lines[0], "the document must start at column 0");
  const root = block(0);
  if (pos < lines.length) fail(lines[pos], "unexpected content after the document");
  return root;
}
