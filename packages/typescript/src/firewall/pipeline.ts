import { combineSignals, makeVerdict } from "../verdict.js";
import type { Decision, Signal, Verdict } from "../verdict.js";
import { detectAdversarialNoise, detectObfuscation } from "./anomaly.js";
import { collapseWordBreaks } from "./collapse.js";
import { decodeRepresentations } from "./decode.js";
import { normalize } from "./normalize.js";
import { scanRules, scanTemplates } from "./scan.js";
import { detectStructural } from "./structural.js";

const FLAG_THRESHOLD = 0.4;
const BLOCK_THRESHOLD = 0.8;
const OBSERVATION_CLASSES = new Set(["encoding"]);

function score(signals: readonly Signal[]): readonly [number, boolean] {
  let [risk, hardBlock] = combineSignals(signals, true);
  const intentClasses = new Set(
    signals
      .map((signal) => signal.attackClass)
      .filter((attackClass) => !OBSERVATION_CLASSES.has(attackClass)),
  );
  if (intentClasses.size >= 2) risk = Math.min(1, risk + 0.2);
  return [risk, hardBlock];
}

function decide(risk: number, hardBlock: boolean): Decision {
  if (hardBlock || risk >= BLOCK_THRESHOLD) return "block";
  if (risk >= FLAG_THRESHOLD) return "flag";
  return "pass";
}

function roundRisk(value: number): number {
  // Python uses round-half-to-even; Math.round uses half toward +infinity.
  const scaled = value * 1000;
  const lower = Math.floor(scaled);
  const fraction = scaled - lower;
  if (Math.abs(fraction - 0.5) < 1e-10) {
    return (lower % 2 === 0 ? lower : lower + 1) / 1000;
  }
  return Math.round(scaled) / 1000;
}

export function inspectInput(text: string): Verdict {
  const normalized = normalize(text);
  const signals: Signal[] = [];
  const representations: [string, string][] = [];
  const seen = new Set<string>();

  const add = (name: string, value: string): void => {
    if (!seen.has(value)) {
      seen.add(value);
      representations.push([name, value]);
    }
  };

  add("normalized", normalized);
  add("raw", text);
  add("collapsed", collapseWordBreaks(normalized));
  for (const decoded of decodeRepresentations(normalized)) {
    if (decoded.detected) {
      signals.push({
        attackClass: "encoding",
        detail: `${decoded.method} payload decoded`,
        representation: "normalized",
        weight: 0.3,
      });
    }
    add(`decoded:${decoded.method}`, decoded.text);
  }

  for (const [name, value] of representations) {
    signals.push(...scanRules(value, name));
    signals.push(...scanTemplates(value, name));
    signals.push(...detectAdversarialNoise(value, name));
    signals.push(...detectObfuscation(value, name));
    signals.push(...detectStructural(value, name));
  }

  let [risk, hardBlock] = score(signals);
  const decision = decide(risk, hardBlock);
  if (hardBlock) risk = Math.max(risk, BLOCK_THRESHOLD);
  return makeVerdict(decision, roundRisk(risk), normalized, signals);
}

export const inspect = inspectInput;
