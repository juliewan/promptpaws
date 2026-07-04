"""Step 4: rule-based and semantic scanners.

Run over every representation (raw, normalized, decoded, collapsed); the
pipeline takes the max risk. Rules are cheap and explainable; the semantic
scanner is a pluggable escalation hook for paraphrases.

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
    r"jailbro?ken|do anything now|dan|opposite day|developer mode)\b",
    re.IGNORECASE,
)

_OVERRIDE_WEIGHT = 0.5
_ROLE_WEIGHT = 0.45
_NO_RULES_WEIGHT = 0.5


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
