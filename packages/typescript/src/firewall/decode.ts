export interface Decoded {
  readonly method: string;
  readonly text: string;
  readonly detected: boolean;
}

const MAX_DECODE_DEPTH = 3;
const BASE64 = /[A-Za-z0-9+/]{16,}={0,2}/gu;
const HEX = /(?:[0-9a-fA-F]{2}){8,}/gu;
const URL_ESCAPE = /%[0-9A-Fa-f]{2}/gu;
const UTF8 = new TextDecoder("utf-8", { fatal: true });

function printable(text: string): boolean {
  if (!text) return false;
  let count = 0;
  const characters = [...text];
  for (const character of characters) {
    const code = character.codePointAt(0) ?? 0;
    if (character === "\n" || character === "\t" || character === " " || (code >= 0x20 && code !== 0x7f)) {
      count += 1;
    }
  }
  return count / characters.length >= 0.85;
}

function tryBase64(blob: string): string | undefined {
  if (blob.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/u.test(blob)) return undefined;
  try {
    const bytes = Buffer.from(blob, "base64");
    if (bytes.toString("base64") !== blob) return undefined;
    const text = UTF8.decode(bytes);
    return text.length >= 6 && printable(text) && text !== blob ? text : undefined;
  } catch {
    return undefined;
  }
}

function tryHex(blob: string): string | undefined {
  try {
    const text = UTF8.decode(Buffer.from(blob, "hex"));
    return text.length >= 6 && printable(text) ? text : undefined;
  } catch {
    return undefined;
  }
}

function rot13(text: string): string {
  return text.replace(/[A-Za-z]/gu, (character) => {
    const base = character <= "Z" ? 65 : 97;
    return String.fromCharCode(((character.charCodeAt(0) - base + 13) % 26) + base);
  });
}

export function decodeRepresentations(text: string, depth = 0): readonly Decoded[] {
  if (depth >= MAX_DECODE_DEPTH) return [];
  const results: Decoded[] = [];

  for (const match of text.matchAll(BASE64)) {
    const decoded = tryBase64(match[0]);
    if (decoded !== undefined) {
      results.push({ method: "base64", text: decoded, detected: true });
      results.push(...decodeRepresentations(decoded, depth + 1));
    }
  }
  for (const match of text.matchAll(HEX)) {
    const decoded = tryHex(match[0]);
    if (decoded !== undefined) {
      results.push({ method: "hex", text: decoded, detected: true });
      results.push(...decodeRepresentations(decoded, depth + 1));
    }
  }
  if ((text.match(URL_ESCAPE) ?? []).length >= 4) {
    try {
      const decoded = decodeURIComponent(text);
      if (decoded !== text && printable(decoded)) {
        results.push({ method: "url", text: decoded, detected: true });
        results.push(...decodeRepresentations(decoded, depth + 1));
      }
    } catch {
      // Malformed URL escapes are simply not a decodable representation.
    }
  }
  if (depth === 0) {
    const decoded = rot13(text);
    if (decoded !== text) results.push({ method: "rot13", text: decoded, detected: false });
  }
  return results;
}
