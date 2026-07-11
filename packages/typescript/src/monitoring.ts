// Layer 5: monitoring. Log every decision with the signals that fired, so
// attempts are visible and real bypasses become new corpus cases.
//
// Local-first by design: the JSONL sink writes lines a Node process can append
// and the Python tooling (`jq`, `promptpaws report`) can read — the serialized
// record uses the same snake_case shape as the Python implementation. A
// server-backed sink is a downstream consumer you add by implementing
// `emit()`; the emit path never changes.
//
// Security note: records retain the raw input, so a log holds attack strings
// and possibly user PII. Access-control it and set a retention policy.

import { appendFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

import type { ScreenResult } from "./screening.js";
import type { SessionAssessment } from "./session.js";
import { signalToJSON } from "./verdict.js";
import type { Signal, SignalJson, Verdict } from "./verdict.js";

export interface DecisionRecordJson {
  readonly ts: string;
  readonly layer: string;
  readonly decision: string;
  readonly risk_score: number;
  readonly signals: readonly SignalJson[];
  readonly session_id: string | null;
  readonly raw_input: string | null;
  readonly extra: Readonly<Record<string, unknown>>;
}

export interface DecisionRecord {
  readonly ts: string;
  readonly layer: "firewall" | "screening" | "session";
  readonly decision: string;
  readonly riskScore: number;
  readonly signals: readonly Signal[];
  readonly sessionId: string | null;
  readonly rawInput: string | null;
  readonly extra: Readonly<Record<string, unknown>>;
  toJSON(): DecisionRecordJson;
}

function makeRecord(
  layer: DecisionRecord["layer"],
  decision: string,
  riskScore: number,
  signals: readonly Signal[],
  sessionId: string | null,
  rawInput: string | null,
  extra: Readonly<Record<string, unknown>>,
): DecisionRecord {
  const ts = new Date().toISOString();
  return {
    ts,
    layer,
    decision,
    riskScore,
    signals,
    sessionId,
    rawInput,
    extra,
    toJSON() {
      return {
        ts,
        layer,
        decision,
        risk_score: riskScore,
        signals: signals.map(signalToJSON),
        session_id: sessionId,
        raw_input: rawInput,
        extra,
      };
    },
  };
}

/** Destination for decision records. Swap this to change where logs go. */
export interface MonitorSink {
  emit(record: DecisionRecord): void;
}

/** Discards records. The default for library use with no logging. */
export class NullSink implements MonitorSink {
  emit(_record: DecisionRecord): void {}
}

/** Keeps records in an array, for tests and in-process inspection. */
export class MemorySink implements MonitorSink {
  readonly records: DecisionRecord[] = [];

  emit(record: DecisionRecord): void {
    this.records.push(record);
  }
}

/** Appends one JSON object per line to a local file. Needs persistent disk. */
export class JsonlSink implements MonitorSink {
  readonly path: string;

  constructor(path: string) {
    this.path = path;
    mkdirSync(dirname(path), { recursive: true });
  }

  emit(record: DecisionRecord): void {
    appendFileSync(this.path, `${JSON.stringify(record)}\n`, "utf8");
  }
}

/** Writes records to stdout. The serverless default: platform logs keep them. */
export class StdoutSink implements MonitorSink {
  emit(record: DecisionRecord): void {
    process.stdout.write(`${JSON.stringify(record)}\n`);
  }
}

/** JSONL sink when `PROMPTPAWS_LOG` is set, otherwise no logging. */
export function sinkFromEnv(): MonitorSink {
  const path = process.env.PROMPTPAWS_LOG;
  return path ? new JsonlSink(path) : new NullSink();
}

export interface FirewallLogOptions {
  readonly rawInput?: string;
  readonly sessionId?: string;
}

export interface ScreeningLogOptions {
  readonly sessionId?: string;
  readonly response?: string;
}

/** Facade that logs each layer's result and passes it through for chaining. */
export class Monitor {
  readonly sink: MonitorSink;

  constructor(sink?: MonitorSink) {
    this.sink = sink ?? new NullSink();
  }

  firewall(verdict: Verdict, options: FirewallLogOptions = {}): Verdict {
    this.sink.emit(
      makeRecord(
        "firewall",
        verdict.decision,
        verdict.riskScore,
        verdict.signals,
        options.sessionId ?? null,
        options.rawInput ?? null,
        { normalized_text: verdict.normalizedText },
      ),
    );
    return verdict;
  }

  screening(result: ScreenResult, options: ScreeningLogOptions = {}): ScreenResult {
    this.sink.emit(
      makeRecord(
        "screening",
        result.decision,
        result.riskScore,
        result.signals,
        options.sessionId ?? null,
        options.response ?? null,
        { replaced: result.decision === "block" },
      ),
    );
    return result;
  }

  session(assessment: SessionAssessment): SessionAssessment {
    this.sink.emit(
      makeRecord(
        "session",
        assessment.action,
        assessment.cumulativeRisk,
        assessment.signals,
        assessment.sessionId,
        null,
        { turn: assessment.turn, turn_risk: assessment.turnRisk },
      ),
    );
    return assessment;
  }
}
