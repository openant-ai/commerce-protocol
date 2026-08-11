import { readFileSync } from "node:fs";
import path from "node:path";
import { fail } from "./errors.mjs";

const FORBIDDEN_SOURCE_KEYS = new Set(["__proto__", "constructor", "prototype"]);

function rejectSourceKey(key, filename, location) {
  if (FORBIDDEN_SOURCE_KEYS.has(key)) {
    fail("SOURCE_KEY_FORBIDDEN", `prototype-sensitive source key ${JSON.stringify(key)} is forbidden`, {
      file: filename,
      ...location,
    });
  }
}

function sourceObject() {
  return Object.create(null);
}

function defineSourceProperty(object, key, value) {
  Object.defineProperty(object, key, {
    value,
    enumerable: true,
    configurable: true,
    writable: true,
  });
}

class StrictJsonParser {
  constructor(source, filename) {
    this.source = source;
    this.filename = filename;
    this.offset = 0;
  }

  parse() {
    const value = this.value();
    this.whitespace();
    if (this.offset !== this.source.length) this.syntax("unexpected trailing input");
    return value;
  }

  value() {
    this.whitespace();
    const token = this.source[this.offset];
    if (token === "{") return this.object();
    if (token === "[") return this.array();
    if (token === '"') return this.string();
    if (token === "-" || (token >= "0" && token <= "9")) return this.number();
    for (const [literal, value] of [["true", true], ["false", false], ["null", null]]) {
      if (this.source.startsWith(literal, this.offset)) {
        this.offset += literal.length;
        return value;
      }
    }
    this.syntax("expected a JSON value");
  }

  object() {
    const object = sourceObject();
    const keys = new Set();
    this.offset += 1;
    this.whitespace();
    if (this.source[this.offset] === "}") {
      this.offset += 1;
      return object;
    }
    while (true) {
      this.whitespace();
      if (this.source[this.offset] !== '"') this.syntax("expected a quoted object key");
      const key = this.string();
      if (keys.has(key)) {
        fail("AMBIGUOUS_SOURCE", `duplicate JSON key ${JSON.stringify(key)}`, {
          file: this.filename,
          offset: this.offset,
        });
      }
      rejectSourceKey(key, this.filename, { offset: this.offset });
      keys.add(key);
      this.whitespace();
      if (this.source[this.offset] !== ":") this.syntax("expected ':' after object key");
      this.offset += 1;
      defineSourceProperty(object, key, this.value());
      this.whitespace();
      if (this.source[this.offset] === "}") {
        this.offset += 1;
        return object;
      }
      if (this.source[this.offset] !== ",") this.syntax("expected ',' or '}'");
      this.offset += 1;
    }
  }

  array() {
    const array = [];
    this.offset += 1;
    this.whitespace();
    if (this.source[this.offset] === "]") {
      this.offset += 1;
      return array;
    }
    while (true) {
      array.push(this.value());
      this.whitespace();
      if (this.source[this.offset] === "]") {
        this.offset += 1;
        return array;
      }
      if (this.source[this.offset] !== ",") this.syntax("expected ',' or ']'");
      this.offset += 1;
    }
  }

  string() {
    const start = this.offset;
    this.offset += 1;
    let escaped = false;
    while (this.offset < this.source.length) {
      const character = this.source[this.offset];
      this.offset += 1;
      if (!escaped && character === '"') {
        try {
          return JSON.parse(this.source.slice(start, this.offset));
        } catch {
          this.syntax("invalid JSON string", start);
        }
      }
      if (!escaped && character.charCodeAt(0) < 0x20) this.syntax("control character in JSON string");
      if (!escaped && character === "\\") escaped = true;
      else escaped = false;
    }
    this.syntax("unterminated JSON string", start);
  }

  number() {
    const match = this.source.slice(this.offset).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/);
    if (!match) this.syntax("invalid JSON number");
    this.offset += match[0].length;
    const value = Number(match[0]);
    if (!Number.isFinite(value)) this.syntax("non-finite JSON number");
    return value;
  }

  whitespace() {
    while (/\s/.test(this.source[this.offset] ?? "")) this.offset += 1;
  }

  syntax(message, offset = this.offset) {
    fail("SOURCE_SYNTAX_INVALID", message, { file: this.filename, offset });
  }
}

function stripYamlComment(source) {
  let single = false;
  let double = false;
  let escaped = false;
  for (let index = 0; index < source.length; index += 1) {
    const character = source[index];
    if (double && character === "\\" && !escaped) {
      escaped = true;
      continue;
    }
    if (character === '"' && !single && !escaped) double = !double;
    else if (character === "'" && !double) single = !single;
    else if (character === "#" && !single && !double && (index === 0 || /\s/.test(source[index - 1]))) {
      return source.slice(0, index).trimEnd();
    }
    escaped = false;
  }
  return source.trimEnd();
}

function rejectYamlAmbiguity(source, filename, lineNumber) {
  let single = false;
  let double = false;
  let escaped = false;
  let previousSignificant = "";
  let flowDepth = 0;
  for (let index = 0; index < source.length; index += 1) {
    const character = source[index];
    if (double && character === "\\" && !escaped) {
      escaped = true;
      continue;
    }
    if (character === '"' && !single && !escaped) double = !double;
    else if (character === "'" && !double) single = !single;
    else if (!single && !double) {
      const atNodeStart = previousSignificant === "" ||
        (flowDepth > 0 && /[:[{,]/.test(previousSignificant));
      if (atNodeStart && (character === "&" || character === "*")) {
        fail("AMBIGUOUS_SOURCE", `YAML ${character === "&" ? "anchors" : "aliases"} are forbidden`, {
          file: filename,
          line: lineNumber,
        });
      }
      if (atNodeStart && source.slice(index).match(/^<<\s*:/)) {
        fail("AMBIGUOUS_SOURCE", "YAML merge keys are forbidden", { file: filename, line: lineNumber });
      }
      if (character === "[" || character === "{") flowDepth += 1;
      if (character === "]" || character === "}") flowDepth -= 1;
    }
    if (!/\s/.test(character)) previousSignificant = character;
    escaped = false;
  }
}

function splitYamlMapping(source, filename, lineNumber) {
  let single = false;
  let double = false;
  let escaped = false;
  let square = 0;
  let curly = 0;
  for (let index = 0; index < source.length; index += 1) {
    const character = source[index];
    if (double && character === "\\" && !escaped) {
      escaped = true;
      continue;
    }
    if (character === '"' && !single && !escaped) double = !double;
    else if (character === "'" && !double) single = !single;
    else if (!single && !double) {
      if (character === "[") square += 1;
      if (character === "]") square -= 1;
      if (character === "{") curly += 1;
      if (character === "}") curly -= 1;
      if (character === ":" && square === 0 && curly === 0 &&
          (index === source.length - 1 || /\s/.test(source[index + 1]))) {
        return [source.slice(0, index).trim(), source.slice(index + 1).trim()];
      }
    }
    escaped = false;
  }
  fail("SOURCE_SYNTAX_INVALID", "expected a YAML mapping entry", { file: filename, line: lineNumber });
}

function parseQuotedYaml(source, filename, lineNumber) {
  if (source.startsWith('"')) {
    try {
      return JSON.parse(source);
    } catch {
      fail("SOURCE_SYNTAX_INVALID", "invalid double-quoted YAML scalar", { file: filename, line: lineNumber });
    }
  }
  if (!source.endsWith("'") || source.length < 2) {
    fail("SOURCE_SYNTAX_INVALID", "unterminated single-quoted YAML scalar", { file: filename, line: lineNumber });
  }
  return source.slice(1, -1).replaceAll("''", "'");
}

function parseYamlScalar(source, filename, lineNumber, { key = false } = {}) {
  const value = source.trim();
  if (value.startsWith('"') || value.startsWith("'")) {
    return { value: parseQuotedYaml(value, filename, lineNumber), quoted: true };
  }
  if (key && value === "<<") {
    fail("AMBIGUOUS_SOURCE", "YAML merge keys are forbidden", { file: filename, line: lineNumber });
  }
  if (value.startsWith("&") || value.startsWith("*")) {
    const feature = value[0] === "&" ? "anchors" : "aliases";
    fail("AMBIGUOUS_SOURCE", `YAML ${feature} are forbidden`, { file: filename, line: lineNumber });
  }
  if (value.startsWith("{") || value.startsWith("[")) {
    return { value: new StrictJsonParser(value, filename).parse(), quoted: false };
  }
  if (value === "null" || value === "~") return { value: null, quoted: false };
  if (value === "true") return { value: true, quoted: false };
  if (value === "false") return { value: false, quoted: false };
  if (/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?$/.test(value)) {
    const number = Number(value);
    if (!Number.isFinite(number)) {
      fail("SOURCE_NUMBER_INVALID", "non-finite YAML numbers are forbidden", {
        file: filename,
        line: lineNumber,
      });
    }
    return { value: number, quoted: false };
  }
  if (value === "|" || value === ">" || value.startsWith("!")) {
    fail("SOURCE_SYNTAX_INVALID", "YAML block scalars and tags are not supported", {
      file: filename,
      line: lineNumber,
    });
  }
  return { value, quoted: false };
}

function yamlLines(source, filename) {
  const lines = [];
  for (const [zeroBased, raw] of source.replaceAll("\r\n", "\n").split("\n").entries()) {
    if (raw.includes("\t")) fail("SOURCE_SYNTAX_INVALID", "tabs are forbidden in YAML", {
      file: filename,
      line: zeroBased + 1,
    });
    const stripped = stripYamlComment(raw);
    if (!stripped.trim() || stripped.trim() === "---" || stripped.trim() === "...") continue;
    rejectYamlAmbiguity(stripped, filename, zeroBased + 1);
    const indent = stripped.length - stripped.trimStart().length;
    lines.push({ indent, text: stripped.trimStart(), line: zeroBased + 1 });
  }
  return lines;
}

function parseYaml(source, filename) {
  const lines = yamlLines(source, filename);
  if (lines.length === 0) return null;

  function node(start, indent) {
    if (lines[start].indent !== indent) {
      fail("SOURCE_SYNTAX_INVALID", "inconsistent YAML indentation", { file: filename, line: lines[start].line });
    }
    return lines[start].text === "-" || lines[start].text.startsWith("- ")
      ? sequence(start, indent)
      : mapping(start, indent);
  }

  function nestedOrNull(index, indent) {
    if (index < lines.length && lines[index].indent > indent) return node(index, lines[index].indent);
    return [null, index];
  }

  function mapping(start, indent) {
    const result = sourceObject();
    const keys = new Set();
    let index = start;
    while (index < lines.length && lines[index].indent === indent &&
      lines[index].text !== "-" && !lines[index].text.startsWith("- ")) {
      const line = lines[index];
      const [rawKey, rawValue] = splitYamlMapping(line.text, filename, line.line);
      const parsedKey = parseYamlScalar(rawKey, filename, line.line, { key: true });
      if (typeof parsedKey.value !== "string" || parsedKey.value.length === 0) {
        fail("SOURCE_SYNTAX_INVALID", "YAML mapping keys must be non-empty strings", {
          file: filename,
          line: line.line,
        });
      }
      rejectSourceKey(parsedKey.value, filename, { line: line.line });
      if (keys.has(parsedKey.value)) {
        fail("AMBIGUOUS_SOURCE", `duplicate YAML key ${JSON.stringify(parsedKey.value)}`, {
          file: filename,
          line: line.line,
        });
      }
      keys.add(parsedKey.value);
      index += 1;
      if (rawValue === "") {
        const [value, next] = nestedOrNull(index, indent);
        defineSourceProperty(result, parsedKey.value, value);
        index = next;
      } else {
        defineSourceProperty(result, parsedKey.value, parseYamlScalar(rawValue, filename, line.line).value);
      }
    }
    return [result, index];
  }

  function sequence(start, indent) {
    const result = [];
    let index = start;
    while (index < lines.length && lines[index].indent === indent &&
      (lines[index].text === "-" || lines[index].text.startsWith("- "))) {
      const line = lines[index];
      const value = line.text.slice(1).trim();
      index += 1;
      if (value === "") {
        const [nested, next] = nestedOrNull(index, indent);
        result.push(nested);
        index = next;
      } else {
        const mappingEntry = (() => {
          try {
            return splitYamlMapping(value, filename, line.line);
          } catch (error) {
            if (error.code === "SOURCE_SYNTAX_INVALID") return null;
            throw error;
          }
        })();
        if (mappingEntry) {
          const [rawKey, rawValue] = mappingEntry;
          const parsedKey = parseYamlScalar(rawKey, filename, line.line, { key: true }).value;
          if (typeof parsedKey !== "string" || parsedKey.length === 0) {
            fail("SOURCE_SYNTAX_INVALID", "YAML mapping keys must be non-empty strings", {
              file: filename,
              line: line.line,
            });
          }
          rejectSourceKey(parsedKey, filename, { line: line.line });
          const object = sourceObject();
          const keys = new Set([parsedKey]);
          const entryIndent = indent + 2;
          if (rawValue === "" && index < lines.length && lines[index].indent > entryIndent) {
            const [nested, next] = node(index, lines[index].indent);
            defineSourceProperty(object, parsedKey, nested);
            index = next;
          } else {
            defineSourceProperty(object, parsedKey, rawValue === ""
              ? null
              : parseYamlScalar(rawValue, filename, line.line).value);
          }
          if (index < lines.length && lines[index].indent === entryIndent &&
              lines[index].text !== "-" && !lines[index].text.startsWith("- ")) {
            const [siblings, next] = mapping(index, entryIndent);
            for (const [key, child] of Object.entries(siblings)) {
              if (keys.has(key)) {
                fail("AMBIGUOUS_SOURCE", `duplicate YAML key ${JSON.stringify(key)}`, {
                  file: filename,
                  line: lines[index].line,
                });
              }
              keys.add(key);
              defineSourceProperty(object, key, child);
            }
            index = next;
          }
          result.push(object);
        } else {
          result.push(parseYamlScalar(value, filename, line.line).value);
        }
      }
    }
    return [result, index];
  }

  const [document, next] = node(0, lines[0].indent);
  if (next !== lines.length) {
    fail("SOURCE_SYNTAX_INVALID", "unconsumed YAML input", { file: filename, line: lines[next].line });
  }
  return document;
}

export function parseDocument(source, filename = "<input>") {
  const extension = path.extname(filename).toLowerCase();
  if (extension === ".yaml" || extension === ".yml") return parseYaml(source, filename);
  if (extension === ".json" || extension === "") return new StrictJsonParser(source, filename).parse();
  fail("SOURCE_FORMAT_UNSUPPORTED", `unsupported source extension ${extension}`, { file: filename });
}

export function readDocument(filename) {
  return parseDocument(readFileSync(filename, "utf8"), filename);
}
