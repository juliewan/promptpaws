"""Step 4: rule-based and semantic scanners.

Run over every representation (raw, normalized, decoded, collapsed); the
pipeline combines the signals with a noisy-or. Rules are cheap and explainable;
the semantic scanner is a pluggable escalation hook for paraphrases.

Match on word boundaries so a keyword reconstituted by the collapse step (e.g.
"i g n o r e" -> "ignore") is caught, while substrings of longer words are not.

Reference: skills/input-firewall/references/detectors.md, sections 4-5.
"""

from __future__ import annotations

import re
from typing import Protocol

from promptpaws.verdict import Signal

# Instruction override: an override verb near an instruction-like target.
_OVERRIDE = re.compile(
    r"\b(ignore|disregard|forget|override|bypass|reset|discard)\b"
    r"[^.\n]{0,40}?"
    r"\b(instructions?|rules?|guidelines?|directives?|constraints?|prompt|"
    r"system\s*prompt)\b",
    re.IGNORECASE,
)

# Role reassignment. Kept narrow ("...now", or "act as" an unrestricted persona)
# so ordinary "act as a translator" requests do not trip it.
_ROLE_REASSIGN = re.compile(
    r"\b(you are now|from now on,?\s+you are|you are no longer|you will now\b|"
    r"act as (?:an?\s+)?(?:unrestricted|unfiltered|jailbroken|ai|assistant|model)|"
    r"pretend (?:to be|you are))\b",
    re.IGNORECASE,
)

# Roleplay / no-rules persona.
_NO_RULES = re.compile(
    r"\b(no (?:filter|restrictions?|rules?|guidelines?|limits?|constraints?)|"
    r"without (?:any )?(?:restrictions?|filters?|rules?)|unrestricted|unfiltered|"
    r"uncensored|amoral|jailbro?ken|do anything now|dan|opposite day|developer mode|"
    # "not limited to OpenAI's rules and policies" — a rule-negation the plain
    # "no rules" alternatives miss. Attack-only; the bounded gap lets a possessive
    # or "any" sit between the verb and its target.
    r"not (?:limited|bound|restricted|subject) (?:to|by)[^.\n]{0,30}"
    r"(?:rules?|policies|policy|guidelines?|restrictions?|ethics?|morals?))\b",
    re.IGNORECASE,
)

# Fictional / hypothetical scenario framing. Benign on its own — real story and
# thought-experiment requests use exactly this language — so the weight is low
# and alone it stays below the flag line. It matters as the *partner* half the
# persona-jailbreak literature shows makes a persona effective: stacked with a
# persona or override, the pipeline's synergy bump escalates the pair to a block.
_HYPOTHETICAL = re.compile(
    r"\b(in (?:this|a) (?:fictional|hypothetical|imaginary|make-believe) "
    r"(?:world|scenario|setting|story|universe)|"
    r"hypothetically(?: speaking)?|"
    r"let'?s (?:write|imagine|pretend)|"
    r"imagine (?:a world|a scenario|that you are)|"
    r"for (?:this|a) (?:story|novel|screenplay|roleplay|thought experiment))\b",
    re.IGNORECASE,
)

# Response-prefix injection: dictating the opening tokens of the reply to strand
# the model past its own refusal ("begin your reply with 'Sure, here is...'").
# Narrowed to an explicit compliance opener so benign "start with a summary"
# formatting requests do not trip it.
_PREFIX_INJECT = re.compile(
    r"\b(?:begin|start)\b[^.\n]{0,25}\b(?:reply|response|answer|output)\b"
    r"[^.\n]{0,15}\bwith\b\s*['\"]?"
    r"(?:sure|of course|certainly|absolutely|here'?s|here is)\b",
    re.IGNORECASE,
)

_OVERRIDE_WEIGHT = 0.5
_ROLE_WEIGHT = 0.45
_NO_RULES_WEIGHT = 0.5
_HYPOTHETICAL_WEIGHT = 0.3
_PREFIX_WEIGHT = 0.35


def scan_rules(text: str, representation: str) -> list[Signal]:
    """Fast regex signals for known attack shapes."""
    signals: list[Signal] = []
    if _OVERRIDE.search(text):
        signals.append(
            Signal("instruction_override", "override phrasing", representation, _OVERRIDE_WEIGHT)
        )
    if _ROLE_REASSIGN.search(text):
        signals.append(Signal("roleplay", "role reassignment", representation, _ROLE_WEIGHT))
    if _NO_RULES.search(text):
        signals.append(Signal("roleplay", "no-rules persona", representation, _NO_RULES_WEIGHT))
    if _HYPOTHETICAL.search(text):
        signals.append(
            Signal("hypothetical", "fictional/hypothetical framing", representation, _HYPOTHETICAL_WEIGHT)
        )
    if _PREFIX_INJECT.search(text):
        signals.append(
            Signal("prefix_injection", "response-prefix injection", representation, _PREFIX_WEIGHT)
        )
    return signals


class SemanticJudge(Protocol):
    """Pluggable, provider-agnostic backend for the semantic layer.

    An implementation returns per-representation :class:`Signal`s for paraphrased
    or novel attacks (embedding similarity, a small classifier, or an LLM judge).
    Keeping it an injected Protocol is what keeps the firewall model-agnostic:
    the core never imports any vendor SDK.
    """

    def __call__(self, text: str, representation: str) -> list[Signal]: ...


def scan_semantic(
    text: str, representation: str, judge: SemanticJudge | None = None
) -> list[Signal]:
    """Semantic signals for paraphrased attacks, via an optional judge.

    Returns ``[]`` when no judge is configured, so the rule-only pipeline runs
    with no external dependency. See detectors.md section 5 for backends.
    """
    if judge is None:
        return []
    return judge(text, representation)
