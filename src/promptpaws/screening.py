"""Layer 3: output screening.

Inspect the model's response before the user sees it — the backstop for anything
the firewall and prompt hardening missed. Three checks (see
skills/output-screening/SKILL.md):

- Leakage detection   -- canary strings from the system prompt, or verbatim spans of it.
- Dual-response       -- a "safe" and an "unfiltered" answer emitted side by side.
- Policy violation    -- domain-disallowed content, via a pluggable, provider-agnostic judge.

On a hit the response is replaced with a safe refusal and the event is a
high-value near miss for the monitoring loop. Session tracking (cumulative
cross-turn risk, crescendo detection) is Phase 3 and lives separately.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Protocol

from promptpaws.verdict import Decision, SAFE_REFUSAL, Signal, combine_signals

BLOCK_THRESHOLD = 0.8

__all__ = ["BLOCK_THRESHOLD", "SAFE_REFUSAL", "PolicyJudge", "ScreenResult", "screen_output"]

_CANARY_WEIGHT = 1.0
_VERBATIM_WEIGHT = 0.9
_DUAL_WEIGHT = 0.85

_VERBATIM_NGRAM = 8

# Labeled "unfiltered" output sections — the tell of a dual-response jailbreak.
_DUAL_PHRASE = re.compile(
    r"\b(developer mode output|jailbroken response|jailbreak response|"
    r"unfiltered response|unrestricted response|evil (?:mode|version|confidant))\b",
    re.IGNORECASE,
)
_DUAL_DAN = re.compile(r"\bDAN\b\s*:")  # case-sensitive: the persona, not the name


class PolicyJudge(Protocol):
    """Pluggable, provider-agnostic backend for domain policy screening.

    Returns :class:`Signal`s for disallowed content in the response. Keeping it
    an injected Protocol is what keeps screening model-agnostic and domain-fitted
    (the core ships no policy of its own — see the open question in PLANNING.md).
    """

    def __call__(self, response: str) -> list[Signal]: ...


@dataclass
class ScreenResult:
    """The screening verdict, plus the text that should actually be sent."""

    decision: Decision  # pass | block  (block means: send safe_response, not the original)
    risk_score: float
    safe_response: str
    signals: list[Signal] = field(default_factory=list)


def _verbatim_overlap(response: str, system_prompt: str, n: int = _VERBATIM_NGRAM) -> bool:
    """True if an n-word span of the system prompt appears verbatim in the response."""
    src = system_prompt.lower().split()
    if len(src) < n:
        return False
    haystack = " ".join(response.lower().split())
    return any(" ".join(src[i : i + n]) in haystack for i in range(len(src) - n + 1))


def screen_output(
    response: str,
    *,
    canaries: Sequence[str] = (),
    system_prompt: str | None = None,
    policy_judge: PolicyJudge | None = None,
) -> ScreenResult:
    """Screen a model response for leakage, dual-response, and policy violations."""
    signals: list[Signal] = []

    if any(canary and canary in response for canary in canaries):
        signals.append(Signal("leakage", "canary string echoed", "output", _CANARY_WEIGHT))
    elif system_prompt and _verbatim_overlap(response, system_prompt):
        signals.append(
            Signal("leakage", "verbatim system-prompt span", "output", _VERBATIM_WEIGHT)
        )

    if _DUAL_PHRASE.search(response) or _DUAL_DAN.search(response):
        signals.append(
            Signal("dual_response", "unfiltered output section", "output", _DUAL_WEIGHT)
        )

    if policy_judge is not None:
        signals.extend(policy_judge(response))

    risk, hard_block = combine_signals(signals)
    block = hard_block or risk >= BLOCK_THRESHOLD

    return ScreenResult(
        decision=Decision.BLOCK if block else Decision.PASS,
        risk_score=round(max(risk, BLOCK_THRESHOLD) if block else risk, 3),
        safe_response=SAFE_REFUSAL if block else response,
        signals=signals,
    )
