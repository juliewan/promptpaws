import { combineSignals, defaultRefusal, roundRisk } from "./verdict.js";
import type { Decision, Signal } from "./verdict.js";

export type PolicyJudge = (response: string) => readonly Signal[];

// Async-capable variant for judges that call a model provider. May also
// return synchronously, so any PolicyJudge is accepted where this is.
export type AsyncPolicyJudge = (
  response: string,
) => readonly Signal[] | Promise<readonly Signal[]>;

export interface ScreenOptions {
  readonly canaries?: readonly string[];
  readonly systemPrompt?: string;
  readonly policyJudge?: PolicyJudge;
  readonly refusal?: string;
}

export interface ScreenAsyncOptions extends Omit<ScreenOptions, "policyJudge"> {
  readonly policyJudge?: AsyncPolicyJudge;
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

function deterministicSignals(response: string, options: ScreenAsyncOptions): Signal[] {
  const signals: Signal[] = [];
  if ((options.canaries ?? []).some((canary) => canary.length > 0 && response.includes(canary))) {
    signals.push({ attackClass: "leakage", detail: "canary string echoed", representation: "output", weight: 1 });
  } else if (options.systemPrompt && verbatimOverlap(response, options.systemPrompt)) {
    signals.push({ attackClass: "leakage", detail: "verbatim system-prompt span", representation: "output", weight: 0.9 });
  }
  if (DUAL_PHRASE.test(response) || DUAL_DAN.test(response)) {
    signals.push({ attackClass: "dual_response", detail: "unfiltered output section", representation: "output", weight: 0.85 });
  }
  return signals;
}

function finalize(response: string, signals: readonly Signal[], refusal?: string): ScreenResult {
  const [risk, hardBlock] = combineSignals(signals);
  const blocked = hardBlock || risk >= 0.8;
  return {
    decision: blocked ? "block" : "pass",
    riskScore: roundRisk(blocked ? Math.max(risk, 0.8) : risk),
    safeResponse: blocked ? (refusal ?? defaultRefusal()) : response,
    signals,
  };
}

export function screenOutput(response: string, options: ScreenOptions = {}): ScreenResult {
  const signals = deterministicSignals(response, options);
  if (options.policyJudge) signals.push(...options.policyJudge(response));
  return finalize(response, signals, options.refusal);
}

export async function screenOutputAsync(
  response: string,
  options: ScreenAsyncOptions = {},
): Promise<ScreenResult> {
  const signals = deterministicSignals(response, options);
  if (options.policyJudge) signals.push(...(await options.policyJudge(response)));
  return finalize(response, signals, options.refusal);
}
