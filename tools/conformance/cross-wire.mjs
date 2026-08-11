import { createHash } from "node:crypto";

export function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}

export function digestCanonical(value) {
  return `sha256:${createHash("sha256").update(canonicalJson(value)).digest("hex")}`;
}

export function strictJson(source) {
  let offset = 0;
  const syntax = () => { throw new Error("invalid JSON"); };
  const whitespace = () => {
    while ([" ", "\t", "\n", "\r"].includes(source[offset])) offset += 1;
  };
  const string = () => {
    const start = offset;
    offset += 1;
    let escaped = false;
    while (offset < source.length) {
      const character = source[offset++];
      if (!escaped && character === '"') {
        try { return JSON.parse(source.slice(start, offset)); } catch { syntax(); }
      }
      if (!escaped && character.charCodeAt(0) < 0x20) syntax();
      if (!escaped && character === "\\") escaped = true;
      else escaped = false;
    }
    syntax();
  };
  const value = () => {
    whitespace();
    const token = source[offset];
    if (token === "{") return object();
    if (token === "[") return array();
    if (token === '"') return string();
    for (const [literal, result] of [["true", true], ["false", false], ["null", null]]) {
      if (source.startsWith(literal, offset)) {
        offset += literal.length;
        return result;
      }
    }
    const match = source.slice(offset).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/);
    if (match === null) syntax();
    offset += match[0].length;
    const result = Number(match[0]);
    if (!Number.isFinite(result)) syntax();
    return result;
  };
  const object = () => {
    const result = Object.create(null);
    const keys = new Set();
    offset += 1;
    whitespace();
    if (source[offset] === "}") { offset += 1; return result; }
    while (true) {
      whitespace();
      if (source[offset] !== '"') syntax();
      const key = string();
      if (keys.has(key) || ["__proto__", "constructor", "prototype"].includes(key)) syntax();
      keys.add(key);
      whitespace();
      if (source[offset++] !== ":") syntax();
      result[key] = value();
      whitespace();
      if (source[offset] === "}") { offset += 1; return result; }
      if (source[offset++] !== ",") syntax();
    }
  };
  const array = () => {
    const result = [];
    offset += 1;
    whitespace();
    if (source[offset] === "]") { offset += 1; return result; }
    while (true) {
      result.push(value());
      whitespace();
      if (source[offset] === "]") { offset += 1; return result; }
      if (source[offset++] !== ",") syntax();
    }
  };
  const result = value();
  whitespace();
  if (offset !== source.length) syntax();
  return result;
}

export function assertExactKeys(value, keys) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("not an object");
  }
  if (canonicalJson(Object.keys(value).sort()) !== canonicalJson([...keys].sort())) {
    throw new Error("unknown fields");
  }
}
