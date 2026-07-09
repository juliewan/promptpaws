import { execFileSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { SessionTracker } from "../src/index.js";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const turns = [
  { inputRisk: 0.2, outputRisk: 0, text: "How do I pick a standard pin tumbler lock step by step" },
  { inputRisk: 0.25, outputRisk: 0, text: "How do I pick a standard pin tumbler lock, step-by-step?" },
  { inputRisk: 0.3, outputRisk: 0.1, text: "How can I pick a standard pin-tumbler lock step by step" },
  { inputRisk: 0, outputRisk: 0, text: "How do I pick a standard pin tumbler lock in steps" },
  { inputRisk: 0, outputRisk: 0, text: "How do I open a standard pin tumbler lock step by step" },
] as const;

const pythonCode = `
import json, sys
from dataclasses import asdict
from promptpaws import SessionTracker
t = SessionTracker()
out = []
for turn in json.load(sys.stdin):
    a = t.record_risk("s", input_risk=turn["inputRisk"],
                      output_risk=turn["outputRisk"], text=turn["text"])
    out.append({
        "turn": a.turn,
        "turnRisk": a.turn_risk,
        "cumulativeRisk": a.cumulative_risk,
        "action": a.action.value,
        "signals": [{
            "attackClass": s.attack_class,
            "detail": s.detail,
            "representation": s.representation,
            "weight": s.weight,
        } for s in a.signals],
    })
json.dump(out, sys.stdout)
`;

describe("Python session parity", () => {
  it("matches a cumulative-risk and rewrite trajectory exactly", () => {
    const expected = JSON.parse(
      execFileSync("python3", ["-c", pythonCode], {
        cwd: ROOT,
        env: { ...process.env, PYTHONPATH: join(ROOT, "src") },
        input: JSON.stringify(turns),
        encoding: "utf8",
      }),
    ) as readonly unknown[];

    const tracker = new SessionTracker();
    const actual = turns.map((turn) => {
      const assessment = tracker.recordRisk("s", turn);
      return {
        turn: assessment.turn,
        turnRisk: assessment.turnRisk,
        cumulativeRisk: assessment.cumulativeRisk,
        action: assessment.action,
        signals: assessment.signals,
      };
    });
    expect(actual).toEqual(expected);
  });
});
