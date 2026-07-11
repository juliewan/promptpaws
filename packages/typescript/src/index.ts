export const VERSION = "0.1.0";

export { inspect, inspectInput, inspectInputAsync } from "./firewall/pipeline.js";
export { normalize } from "./firewall/normalize.js";
export { collapseWordBreaks } from "./firewall/collapse.js";
export { decodeRepresentations } from "./firewall/decode.js";
export type { SemanticJudge } from "./firewall/scan.js";
export { guard, guardAsync } from "./guard.js";
export type {
  Guarded,
  GuardedAllowed,
  GuardedBlocked,
  GuardAsyncOptions,
  GuardOptions,
} from "./guard.js";
export { harden, newCanary, newMarker, spotlight } from "./hardening.js";
export type {
  ChatMessage,
  HardenOptions,
  ModelCall,
} from "./hardening.js";
export { llmJudge, llmPolicyJudge } from "./judge.js";
export type { Complete, JudgeOptions, PolicyJudgeOptions } from "./judge.js";
export {
  JsonlSink,
  MemorySink,
  Monitor,
  NullSink,
  sinkFromEnv,
  StdoutSink,
} from "./monitoring.js";
export type {
  DecisionRecord,
  DecisionRecordJson,
  FirewallLogOptions,
  MonitorSink,
  ScreeningLogOptions,
} from "./monitoring.js";
export { screenOutput, screenOutputAsync } from "./screening.js";
export type {
  AsyncPolicyJudge,
  PolicyJudge,
  ScreenAsyncOptions,
  ScreenOptions,
  ScreenResult,
} from "./screening.js";
export { SessionTracker, similarityRatio } from "./session.js";
export type {
  RecordOptions,
  RecordRiskOptions,
  SessionAction,
  SessionAssessment,
  SessionState,
} from "./session.js";
export {
  combineSignals,
  defaultRefusal,
  HARD_BLOCK_WEIGHT,
  SAFE_REFUSAL,
} from "./verdict.js";
export type {
  Decision,
  Signal,
  SignalJson,
  Verdict,
  VerdictJson,
} from "./verdict.js";
