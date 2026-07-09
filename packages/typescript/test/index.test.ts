import { describe, expect, it } from "vitest";

import { VERSION } from "../src/index.js";
import type { Verdict } from "../src/index.js";

describe("package scaffold", () => {
  it("exports its version", () => {
    expect(VERSION).toBe("0.1.0");
  });

  it("defines the camelCase API and snake_case wire contract", () => {
    const verdict: Verdict = {
      decision: "pass",
      riskScore: 0,
      normalizedText: "hello",
      signals: [],
      toJSON() {
        return {
          decision: this.decision,
          risk_score: this.riskScore,
          normalized_text: this.normalizedText,
          signals: [],
        };
      },
    };

    expect(verdict.toJSON()).toEqual({
      decision: "pass",
      risk_score: 0,
      normalized_text: "hello",
      signals: [],
    });
  });
});
