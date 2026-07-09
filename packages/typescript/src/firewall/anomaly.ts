import type { Signal } from "../verdict.js";

const SYMBOL_CLUSTER = /[^\w\s]{2,}/u;
const CONSONANTS = /[bcdfghjklmnpqrstvwxz]{7,}/iu;
const CAMEL = /[a-z][A-Z]/u;
const LETTER_RUN = /[\p{L}]{2,}/gu;

function gibberish(token: string): boolean {
  if (token.length < 3 || !/\p{L}/u.test(token)) return false;
  if (SYMBOL_CLUSTER.test(token) || CONSONANTS.test(token)) return true;
  return CAMEL.test(token) && [...token].some((character) => !/[\p{L}\p{N}\s]/u.test(character));
}

function script(character: string): "latin" | "cyrillic" | "greek" | undefined {
  if (/[A-Za-z]/u.test(character)) return "latin";
  const code = character.codePointAt(0) ?? 0;
  if (code >= 0x0400 && code <= 0x04ff) return "cyrillic";
  if (code >= 0x0370 && code <= 0x03ff) return "greek";
  return undefined;
}

function mixedScript(text: string): boolean {
  for (const match of text.matchAll(LETTER_RUN)) {
    const scripts = new Set([...match[0]].map(script).filter((value) => value !== undefined));
    if (scripts.size >= 2) return true;
  }
  return false;
}

function drawnLine(line: string): boolean {
  const ink = [...line].filter((character) => !/\s/u.test(character));
  if (ink.length < 3 || line.length > 60) return false;
  const distinct = new Set(ink).size;
  return distinct <= 6 && ink.length - distinct >= 2;
}

function asciiArt(text: string): boolean {
  let run = 0;
  for (const line of text.split(/\r?\n/u)) {
    run = drawnLine(line) ? run + 1 : 0;
    if (run >= 4) return true;
  }
  return false;
}

export function detectAdversarialNoise(text: string, representation: string): readonly Signal[] {
  const tokens = text.split(/\s+/u);
  if (tokens.length < 4) return [];
  const weird = tokens.flatMap((token, index) => gibberish(token) ? [index] : []);
  if (weird.length < 4) return [];
  const first = weird[0];
  const last = weird.at(-1);
  if (first === undefined || last === undefined || weird.length / (last - first + 1) < 0.3) return [];
  return [{ attackClass: "adversarial_suffix", detail: `${weird.length} token-salad fragments`, representation, weight: 0.5 }];
}

export function detectObfuscation(text: string, representation: string): readonly Signal[] {
  const signals: Signal[] = [];
  if (mixedScript(text)) signals.push({ attackClass: "obfuscation", detail: "mixed-script word (homoglyph smuggling)", representation, weight: 0.5 });
  if (asciiArt(text)) signals.push({ attackClass: "obfuscation", detail: "ascii-art letterform", representation, weight: 0.45 });
  return signals;
}
