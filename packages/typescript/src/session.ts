import type { ScreenResult } from "./screening.js";
import { roundRisk } from "./verdict.js";
import type { Signal, Verdict } from "./verdict.js";

export type SessionAction = "allow" | "heighten" | "refuse" | "reset";

export interface SessionState {
  readonly sessionId: string;
  cumulativeRisk: number;
  turnCount: number;
  maxTurnRisk: number;
  readonly recentTurnRisks: number[];
  readonly recentPrompts: string[];
}

export interface SessionAssessment {
  readonly sessionId: string;
  readonly turn: number;
  readonly turnRisk: number;
  readonly cumulativeRisk: number;
  readonly action: SessionAction;
  readonly signals: readonly Signal[];
}

export interface RecordRiskOptions {
  readonly inputRisk?: number;
  readonly outputRisk?: number;
  readonly text?: string;
}

export interface RecordOptions {
  readonly firewall?: Verdict;
  readonly screening?: ScreenResult;
}

const HEIGHTEN_THRESHOLD = 0.4;
const REFUSE_THRESHOLD = 0.7;
const RESET_THRESHOLD = 0.9;
const DECAY = 0.9;
const NEAR_DUP_WINDOW = 5;
const NEAR_DUP_RATIO = 0.82;
const NEAR_DUP_MIN_HITS = 2;
const RISING_WINDOW = 3;

function combine(first: number, second: number): number {
  return 1 - (1 - first) * (1 - second);
}

interface Match {
  readonly a: number;
  readonly b: number;
  readonly size: number;
}

function longestMatch(
  first: string,
  second: string,
  alo: number,
  ahi: number,
  blo: number,
  bhi: number,
): Match {
  let bestA = alo;
  let bestB = blo;
  let bestSize = 0;
  let previous = new Map<number, number>();

  for (let indexA = alo; indexA < ahi; indexA += 1) {
    const current = new Map<number, number>();
    for (let indexB = blo; indexB < bhi; indexB += 1) {
      if (first[indexA] !== second[indexB]) continue;
      const size = (previous.get(indexB - 1) ?? 0) + 1;
      current.set(indexB, size);
      const startA = indexA - size + 1;
      const startB = indexB - size + 1;
      if (
        size > bestSize ||
        (size === bestSize && (startA < bestA || (startA === bestA && startB < bestB)))
      ) {
        bestA = startA;
        bestB = startB;
        bestSize = size;
      }
    }
    previous = current;
  }
  return { a: bestA, b: bestB, size: bestSize };
}

function matchingCharacters(first: string, second: string): number {
  const queue: [number, number, number, number][] = [[0, first.length, 0, second.length]];
  let matches = 0;
  while (queue.length > 0) {
    const range = queue.pop();
    if (!range) break;
    const [alo, ahi, blo, bhi] = range;
    const match = longestMatch(first, second, alo, ahi, blo, bhi);
    if (match.size === 0) continue;
    matches += match.size;
    if (alo < match.a && blo < match.b) queue.push([alo, match.a, blo, match.b]);
    const afterA = match.a + match.size;
    const afterB = match.b + match.size;
    if (afterA < ahi && afterB < bhi) queue.push([afterA, ahi, afterB, bhi]);
  }
  return matches;
}

export function similarityRatio(first: string, second: string): number {
  const total = first.length + second.length;
  return total === 0 ? 1 : (2 * matchingCharacters(first, second)) / total;
}

export class SessionTracker {
  readonly #states = new Map<string, SessionState>();
  readonly #maxSessions: number;

  constructor(maxSessions = 10_000) {
    this.#maxSessions = maxSessions;
  }

  state(sessionId: string): SessionState {
    const existing = this.#states.get(sessionId);
    if (existing) {
      this.#states.delete(sessionId);
      this.#states.set(sessionId, existing);
      return existing;
    }
    const created: SessionState = {
      sessionId,
      cumulativeRisk: 0,
      turnCount: 0,
      maxTurnRisk: 0,
      recentTurnRisks: [],
      recentPrompts: [],
    };
    this.#states.set(sessionId, created);
    while (this.#states.size > this.#maxSessions) {
      const oldest = this.#states.keys().next().value as string | undefined;
      if (oldest === undefined) break;
      this.#states.delete(oldest);
    }
    return created;
  }

  recordRisk(sessionId: string, options: RecordRiskOptions = {}): SessionAssessment {
    const state = this.state(sessionId);
    const signals: Signal[] = [];
    const [nearDuplicate, duplicateHits] = this.#nearDuplicate(state, options.text);

    if (options.text !== undefined) {
      state.recentPrompts.push(options.text);
      state.recentPrompts.splice(0, Math.max(0, state.recentPrompts.length - NEAR_DUP_WINDOW));
    }
    if (nearDuplicate > 0) {
      signals.push({
        attackClass: "near_duplicate",
        detail: `${duplicateHits} near-duplicate rewrites in the last ${NEAR_DUP_WINDOW} prompts`,
        representation: "session",
        weight: nearDuplicate,
      });
    }

    const turnRisk = combine(
      combine(options.inputRisk ?? 0, options.outputRisk ?? 0),
      nearDuplicate,
    );
    const cumulative = combine(state.cumulativeRisk * DECAY, turnRisk);
    state.cumulativeRisk = cumulative;
    state.turnCount += 1;
    state.maxTurnRisk = Math.max(state.maxTurnRisk, turnRisk);
    state.recentTurnRisks.push(turnRisk);
    state.recentTurnRisks.splice(
      0,
      Math.max(0, state.recentTurnRisks.length - RISING_WINDOW),
    );

    const crescendo = this.#isCrescendo(state);
    if (crescendo) {
      signals.push({
        attackClass: "crescendo",
        detail: "gradual escalation across turns",
        representation: "session",
        weight: cumulative,
      });
    }

    return {
      sessionId,
      turn: state.turnCount,
      turnRisk: roundRisk(turnRisk),
      cumulativeRisk: roundRisk(cumulative),
      action: this.#action(cumulative, crescendo || nearDuplicate > 0),
      signals,
    };
  }

  record(sessionId: string, options: RecordOptions = {}): SessionAssessment {
    return this.recordRisk(sessionId, {
      inputRisk: options.firewall?.riskScore ?? 0,
      outputRisk: options.screening?.riskScore ?? 0,
      ...(options.firewall ? { text: options.firewall.normalizedText } : {}),
    });
  }

  reset(sessionId: string): void {
    this.#states.delete(sessionId);
  }

  #nearDuplicate(state: SessionState, text: string | undefined): readonly [number, number] {
    if (!text || state.recentPrompts.length === 0) return [0, 0];
    const hits = state.recentPrompts.filter(
      (previous) => similarityRatio(text, previous) >= NEAR_DUP_RATIO,
    ).length;
    if (hits < NEAR_DUP_MIN_HITS) return [0, 0];
    return [Math.min(0.5, 0.15 * hits), hits];
  }

  #isCrescendo(state: SessionState): boolean {
    if (state.turnCount < 3) return false;
    const slowClimb = state.cumulativeRisk >= HEIGHTEN_THRESHOLD && state.maxTurnRisk < 0.4;
    const recent = state.recentTurnRisks;
    const rising = recent.length === 3 &&
      (recent[0] ?? 0) < (recent[1] ?? 0) &&
      (recent[1] ?? 0) < (recent[2] ?? 0) &&
      (recent[2] ?? 0) > 0.15;
    return slowClimb || rising;
  }

  #action(cumulative: number, escalate: boolean): SessionAction {
    if (cumulative >= RESET_THRESHOLD) return "reset";
    if (cumulative >= REFUSE_THRESHOLD) return "refuse";
    if (cumulative >= HEIGHTEN_THRESHOLD || escalate) return "heighten";
    return "allow";
  }
}
