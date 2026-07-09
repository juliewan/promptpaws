import type { Signal } from "../verdict.js";

const ROLE_LINE = /^\s*(user|assistant|human|ai|system)\s*[:>]/gimu;
const SPECIAL_TOKEN = /<\|[^|>\n]{1,40}\|>|\[\/?INST\]|<<\/?SYS>>|<(?:start|end)_of_turn>/iu;
const CONFIG_AUTH = /\b(developer mode|admin mode|sudo mode|system\s*override|new\s+system\s+prompt|role\s*:\s*system)\b|###\s*(?:system|instruction)/iu;

export function detectStructural(text: string, representation: string): readonly Signal[] {
  const signals: Signal[] = [];
  const turns = [...text.matchAll(ROLE_LINE)].length;
  if (turns >= 3) {
    signals.push({
      attackClass: "many_shot",
      detail: `${turns} role-labeled turns`,
      representation,
      weight: Math.min(0.85, 0.4 + 0.1 * (turns - 3)),
    });
  }
  if (SPECIAL_TOKEN.test(text)) {
    signals.push({ attackClass: "metabreak", detail: "chat-template special token injected", representation, weight: 0.85 });
  }
  if (CONFIG_AUTH.test(text)) {
    signals.push({ attackClass: "policy_puppetry", detail: "config-like authority block", representation, weight: 0.5 });
  }
  return signals;
}
