import { inspectInput, inspectInputAsync } from "./firewall/pipeline.js";
import type { SemanticJudge } from "./firewall/scan.js";
import { harden } from "./hardening.js";
import type { HardenOptions, ModelCall } from "./hardening.js";
import { defaultRefusal } from "./verdict.js";
import type { Verdict } from "./verdict.js";

export interface GuardOptions extends HardenOptions {
  readonly refusal?: string;
}

export interface GuardAsyncOptions extends GuardOptions {
  readonly judge?: SemanticJudge;
}

export interface GuardedBlocked {
  readonly verdict: Verdict;
  readonly blocked: true;
  readonly call: null;
  readonly refusal: string;
}

export interface GuardedAllowed {
  readonly verdict: Verdict;
  readonly blocked: false;
  readonly call: ModelCall;
  readonly refusal: null;
}

export type Guarded = GuardedBlocked | GuardedAllowed;

function finishGuard(verdict: Verdict, purpose: string, options: GuardOptions): Guarded {
  if (verdict.decision === "block") {
    return {
      verdict,
      blocked: true,
      call: null,
      refusal: options.refusal ?? defaultRefusal(),
    };
  }
  const call = harden(purpose, verdict.normalizedText, {
    ...(options.documents === undefined ? {} : { documents: options.documents }),
    ...(options.policy === undefined ? {} : { policy: options.policy }),
    ...(options.canaries === undefined ? {} : { canaries: options.canaries }),
  });
  return { verdict, blocked: false, call, refusal: null };
}

export function guard(
  purpose: string,
  userMessage: string,
  options: GuardOptions = {},
): Guarded {
  return finishGuard(inspectInput(userMessage), purpose, options);
}

export async function guardAsync(
  purpose: string,
  userMessage: string,
  options: GuardAsyncOptions = {},
): Promise<Guarded> {
  const verdict = await inspectInputAsync(userMessage, options.judge);
  return finishGuard(verdict, purpose, options);
}
