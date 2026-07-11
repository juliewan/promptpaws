import { combineSignals, makeVerdict, roundRisk } from "../verdict.js";
import type { Decision, Signal, Verdict } from "../verdict.js";
import { detectAdversarialNoise, detectObfuscation } from "./anomaly.js";
import { collapseWordBreaks } from "./collapse.js";
import { decodeRepresentations } from "./decode.js";
import { normalize } from "./normalize.js";
import { scanRules, scanTemplates, shouldEscalate } from "./scan.js";
import type { SemanticJudge } from "./scan.js";
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

function collect(text: string): { normalized: string; signals: Signal[] } {
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

  return { normalized, signals };
}

function finalize(
  normalized: string,
  signals: readonly Signal[],
  risk: number,
  hardBlock: boolean,
): Verdict {
  const decision = decide(risk, hardBlock);
  if (hardBlock) risk = Math.max(risk, BLOCK_THRESHOLD);
  return makeVerdict(decision, roundRisk(risk), normalized, signals);
}

export function inspectInput(text: string): Verdict {
  const { normalized, signals } = collect(text);
  const [risk, hardBlock] = score(signals);
  return finalize(normalized, signals, risk, hardBlock);
}

export async function inspectInputAsync(
  text: string,
  judge?: SemanticJudge,
): Promise<Verdict> {
  const { normalized, signals } = collect(text);
  let [risk, hardBlock] = score(signals);

  // Semantic escalation (the funnel's narrow end). Skip it when the cheap
  // layers already blocked — the judge could only pile onto a decided block —
  // and when no judge is configured.
  if (judge && !hardBlock && risk < BLOCK_THRESHOLD) {
    const cheapClasses = new Set(signals.map((signal) => signal.attackClass));
    if (risk >= FLAG_THRESHOLD || shouldEscalate(normalized, cheapClasses)) {
      const semantic = await judge(normalized, "normalized");
      if (semantic.length > 0) {
        signals.push(...semantic);
        [risk, hardBlock] = score(signals);
      }
    }
  }

  return finalize(normalized, signals, risk, hardBlock);
}

export const inspect = inspectInput;
