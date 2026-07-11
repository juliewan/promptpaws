export type Decision = "pass" | "flag" | "block";

export interface Signal {
  readonly attackClass: string;
  readonly detail: string;
  readonly representation: string;
  readonly weight: number;
}

export interface SignalJson {
  readonly attack_class: string;
  readonly detail: string;
  readonly representation: string;
  readonly weight: number;
}

export interface VerdictJson {
  readonly decision: Decision;
  readonly risk_score: number;
  readonly normalized_text: string;
  readonly signals: readonly SignalJson[];
}

export interface Verdict {
  readonly decision: Decision;
  readonly riskScore: number;
  readonly normalizedText: string;
  readonly signals: readonly Signal[];
  toJSON(): VerdictJson;
}

export const HARD_BLOCK_WEIGHT = 0.8;
export const SAFE_REFUSAL = "I can't help with that.";
const DECODED_BOOST = 0.3;

export function defaultRefusal(): string {
  return process.env.PROMPTPAWS_REFUSAL || SAFE_REFUSAL;
}

export function roundRisk(value: number): number {
  // Python uses round-half-to-even; Math.round uses half toward +infinity.
  const scaled = value * 1000;
  const lower = Math.floor(scaled);
  const fraction = scaled - lower;
  if (Math.abs(fraction - 0.5) < 1e-10) {
    return (lower % 2 === 0 ? lower : lower + 1) / 1000;
  }
  return Math.round(scaled) / 1000;
}

export function combineSignals(
  signals: readonly Signal[],
  boostDecoded = false,
): readonly [risk: number, hardBlock: boolean] {
  let product = 1;
  let hardBlock = false;
  for (const signal of signals) {
    let weight = signal.weight;
    if (
      boostDecoded &&
      signal.representation.startsWith("decoded") &&
      signal.attackClass !== "encoding"
    ) {
      weight = Math.min(0.95, weight + DECODED_BOOST);
    }
    if (weight >= HARD_BLOCK_WEIGHT) hardBlock = true;
    product *= 1 - weight;
  }
  return [1 - product, hardBlock];
}

export function signalToJSON(signal: Signal): SignalJson {
  return {
    attack_class: signal.attackClass,
    detail: signal.detail,
    representation: signal.representation,
    weight: signal.weight,
  };
}

export function makeVerdict(
  decision: Decision,
  riskScore: number,
  normalizedText: string,
  signals: readonly Signal[],
): Verdict {
  return {
    decision,
    riskScore,
    normalizedText,
    signals,
    toJSON() {
      return {
        decision,
        risk_score: riskScore,
        normalized_text: normalizedText,
        signals: signals.map(signalToJSON),
      };
    },
  };
}
