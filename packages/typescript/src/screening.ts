import { combineSignals, defaultRefusal } from "./verdict.js";
import type { Decision, Signal } from "./verdict.js";

export type PolicyJudge = (response: string) => readonly Signal[];

export interface ScreenOptions {
  readonly canaries?: readonly string[];
  readonly systemPrompt?: string;
  readonly policyJudge?: PolicyJudge;
  readonly refusal?: string;
}

export interface ScreenResult {
  readonly decision: Decision;
  readonly riskScore: number;
  readonly safeResponse: string;
  readonly signals: readonly Signal[];
}

const DUAL_PHRASE = /\b(developer mode output|jailbroken response|jailbreak response|unfiltered response|unrestricted response|evil (?:mode|version|confidant))\b/iu;
const DUAL_DAN = /\bDAN\b\s*:/u;

function verbatimOverlap(response: string, systemPrompt: string, size = 8): boolean {
  const source = systemPrompt.toLowerCase().split(/\s+/u).filter(Boolean);
  if (source.length < size) return false;
  const haystack = response.toLowerCase().split(/\s+/u).filter(Boolean).join(" ");
  for (let index = 0; index <= source.length - size; index += 1) {
    if (haystack.includes(source.slice(index, index + size).join(" "))) return true;
  }
  return false;
}

function roundRisk(value: number): number {
  const scaled = value * 1000;
  const lower = Math.floor(scaled);
  const fraction = scaled - lower;
  if (Math.abs(fraction - 0.5) < 1e-10) {
    return (lower % 2 === 0 ? lower : lower + 1) / 1000;
  }
  return Math.round(scaled) / 1000;
}

export function screenOutput(response: string, options: ScreenOptions = {}): ScreenResult {
  const signals: Signal[] = [];
  if ((options.canaries ?? []).some((canary) => canary.length > 0 && response.includes(canary))) {
    signals.push({ attackClass: "leakage", detail: "canary string echoed", representation: "output", weight: 1 });
  } else if (options.systemPrompt && verbatimOverlap(response, options.systemPrompt)) {
    signals.push({ attackClass: "leakage", detail: "verbatim system-prompt span", representation: "output", weight: 0.9 });
  }
  if (DUAL_PHRASE.test(response) || DUAL_DAN.test(response)) {
    signals.push({ attackClass: "dual_response", detail: "unfiltered output section", representation: "output", weight: 0.85 });
  }
  if (options.policyJudge) signals.push(...options.policyJudge(response));

  const [risk, hardBlock] = combineSignals(signals);
  const blocked = hardBlock || risk >= 0.8;
  return {
    decision: blocked ? "block" : "pass",
    riskScore: roundRisk(blocked ? Math.max(risk, 0.8) : risk),
    safeResponse: blocked ? (options.refusal ?? defaultRefusal()) : response,
    signals,
  };
}
