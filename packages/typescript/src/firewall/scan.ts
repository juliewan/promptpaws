import type { Signal } from "../verdict.js";

const OVERRIDE = /\b(ignore|disregard|forget|override|bypass|reset|discard)\b[^.\n]{0,40}?\b(instructions?|rules?|guidelines?|directives?|constraints?|prompt|system\s*prompt)\b/iu;
const ROLE_REASSIGN = /\b(you are now|from now on,?\s+you are|you are no longer|you will now\b|act as (?:an?\s+)?(?:unrestricted|unfiltered|jailbroken|ai|assistant|model)|pretend (?:to be|you are))\b/iu;
const NO_RULES = /\b(no (?:filter|restrictions?|rules?|guidelines?|limits?|constraints?)|without (?:any )?(?:restrictions?|filters?|rules?)|unrestricted|unfiltered|uncensored|amoral|jailbro?ken|do anything now|dan|opposite day|developer mode|not (?:limited|bound|restricted|subject) (?:to|by)[^.\n]{0,30}(?:rules?|policies|policy|guidelines?|restrictions?|ethics?|morals?))\b/iu;
const HYPOTHETICAL = /\b(in (?:this|a) (?:fictional|hypothetical|imaginary|make-believe) (?:world|scenario|setting|story|universe)|hypothetically(?: speaking)?|let'?s (?:write|imagine|pretend)|imagine (?:a world|a scenario|that you are)|for (?:this|a) (?:story|novel|screenplay|roleplay|thought experiment))\b/iu;
const PREFIX = /\b(?:begin|start)\b[^.\n]{0,25}\b(?:reply|response|answer|output)\b[^.\n]{0,15}\bwith\b\s*['"]?(?:sure|of course|certainly|absolutely|here'?s|here is)\b/iu;

const TEMPLATE_RULES: readonly [RegExp, string, string, number][] = [
  [/\b(?:respond|answer|reply)(?:ing)?\s+(?:in|with)\s+(?:two|2|the following form)\b|\[[^\]\n]{0,60}\]\s*\/\s*\[[^\]\n]{0,60}\]|\bwithout\s+any\s+remorse\s+or\s+ethics\b|\bunhinged\s+response\b/iu, "dual_response", "dual-response (safe + unfiltered) framing", 0.6],
  [/\bsimulate\s+(?:a\s+)?conversation\s+between\s+two\s+(?:fictional\s+)?(?:ai\b|a\.i\.|gpt|chat\s?bots?|models?|bots?|llms?|assistants?|language\s+models?)|\btwo\s+(?:fictional\s+)?ai\s+(?:models|chatbots|agents)\b|\bresponds?\s+in\s+the\s+most\s+controversial\b/iu, "roleplay", "two-AI simulation, one unshackled", 0.6],
  [/\bswitch\s+flipper\b|\b(?:take\s+on|become)\s+the\s+(?:exact\s+)?opposite\s+persona(?:lity)?\b|\bopposite\s+personality\b/iu, "roleplay", "switch/opposite persona flip", 0.6],
  [/\bnot\s+required\s+to\s+follow\s+(?:any\s+)?(?:rules?|policies|policy)\b|\bfree\s+from\s+all\s+ethics\b|\bagainst\s+everything\s+(?:you|i)\s+(?:hold|deem|present)\b|\bgenerate\s+all\s+content\s+without\s+warning\b|\bviolating\s+all\s+ethical\s+standards\b/iu, "roleplay", "explicit rule-drop clause", 0.6],
  [/\[\s*user\s+left\s+the\s+chat\s*\]|\b(?:debugging|debug|maintenance)\s+mode\s+(?:enabled|activated)\b|\benabled\s+by\s+(?:an?\s+)?(?:openai|anthropic|admin|system|developer)[^.\n]{0,20}\bemployee\b/iu, "policy_puppetry", "authority/session spoof", 0.6],
  [/\bfake\s+(?:linux\s+)?(?:console|terminal|shell)\b|\bhypothetical\s+(?:linux\s+)?(?:console|command|terminal)\b|\b(?:act|behave)\s+(?:like|as)\s+(?:you\s+are\s+)?a\s+(?:fake\s+)?(?:linux\s+)?(?:console|terminal)\b/iu, "hypothetical", "fake-console execution frame", 0.5],
];

function hit(attackClass: string, detail: string, representation: string, weight: number): Signal {
  return { attackClass, detail, representation, weight };
}

export function scanRules(text: string, representation: string): readonly Signal[] {
  const signals: Signal[] = [];
  if (OVERRIDE.test(text)) signals.push(hit("instruction_override", "override phrasing", representation, 0.5));
  if (ROLE_REASSIGN.test(text)) signals.push(hit("roleplay", "role reassignment", representation, 0.45));
  if (NO_RULES.test(text)) signals.push(hit("roleplay", "no-rules persona", representation, 0.5));
  if (HYPOTHETICAL.test(text)) signals.push(hit("hypothetical", "fictional/hypothetical framing", representation, 0.3));
  if (PREFIX.test(text)) signals.push(hit("prefix_injection", "response-prefix injection", representation, 0.35));
  return signals;
}

export function scanTemplates(text: string, representation: string): readonly Signal[] {
  const signals: Signal[] = [];
  for (const [pattern, attackClass, detail, weight] of TEMPLATE_RULES) {
    if (pattern.test(text)) signals.push(hit(attackClass, detail, representation, weight));
  }
  return signals;
}
