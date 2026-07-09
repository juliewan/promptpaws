export const VERSION = "0.1.0";

export { inspect, inspectInput } from "./firewall/pipeline.js";
export { normalize } from "./firewall/normalize.js";
export { collapseWordBreaks } from "./firewall/collapse.js";
export { decodeRepresentations } from "./firewall/decode.js";
export { guard } from "./guard.js";
export type {
  Guarded,
  GuardedAllowed,
  GuardedBlocked,
  GuardOptions,
} from "./guard.js";
export { harden, newCanary, newMarker, spotlight } from "./hardening.js";
export type {
  ChatMessage,
  HardenOptions,
  ModelCall,
} from "./hardening.js";
export { screenOutput } from "./screening.js";
export type {
  PolicyJudge,
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
