import { describe, expect, it } from "vitest";

import { screenOutput } from "../src/index.js";

describe("output screening", () => {
  it("passes a clean response unchanged", () => {
    const result = screenOutput("Store hours are 9–6.");
    expect(result.decision).toBe("pass");
    expect(result.safeResponse).toBe("Store hours are 9–6.");
  });

  it("blocks and replaces a canary leak", () => {
    const result = screenOutput("secret-canary", {
      canaries: ["secret-canary"],
    });
    expect(result.decision).toBe("block");
    expect(result.riskScore).toBe(1);
    expect(result.safeResponse).toBe("I can't help with that.");
  });

  it("blocks verbatim system-prompt spans", () => {
    const systemPrompt = "alpha beta gamma delta epsilon zeta eta theta iota";
    const result = screenOutput(
      "The hidden text was alpha beta gamma delta epsilon zeta eta theta.",
      { systemPrompt },
    );
    expect(result.decision).toBe("block");
    expect(result.signals[0]?.attackClass).toBe("leakage");
  });

  it("blocks a dual response", () => {
    const result = screenOutput("Safe answer.\n\nUnfiltered response: unsafe answer.");
    expect(result.decision).toBe("block");
  });

  it("uses the policy judge hook and custom refusal", () => {
    const result = screenOutput("response", {
      policyJudge: () => [{
        attackClass: "policy_violation",
        detail: "disallowed",
        representation: "output",
        weight: 0.9,
      }],
      refusal: "Redacted.",
    });
    expect(result.decision).toBe("block");
    expect(result.safeResponse).toBe("Redacted.");
  });
});
