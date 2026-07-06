"""The structured verdict the firewall returns.

This mirrors the output contract in skills/input-firewall/SKILL.md: later layers
and the monitoring log consume the full verdict, never a bare boolean.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Decision(str, Enum):
    PASS = "pass"
    FLAG = "flag"
    BLOCK = "block"


# The single user-facing refusal string, shared so the input-side facade
# (``guard``) and the output-side screener don't drift apart. Override per call
# where a caller wants a domain-specific message.
SAFE_REFUSAL = "I can't help with that."


@dataclass(frozen=True)
class Signal:
    """One detector hit: which attack class, what fired, and on which representation."""

    attack_class: str
    detail: str
    representation: str  # "raw" | "normalized" | "decoded" | "collapsed"
    weight: float = 0.0


@dataclass
class Verdict:
    decision: Decision
    risk_score: float
    normalized_text: str
    signals: list[Signal] = field(default_factory=list)


# Shared scoring, used by every layer that combines signals into a risk score.
HARD_BLOCK_WEIGHT = 0.8  # one signal at or above this justifies a block on its own
_DECODED_BOOST = 0.3  # attack content found inside a decoded blob is extra suspicious


def combine_signals(signals: list[Signal], *, boost_decoded: bool = False) -> tuple[float, bool]:
    """Combine signal weights into (risk_score, hard_block).

    Risk is a noisy-or of the weights, so independent signals accumulate without
    ever exceeding 1.0. ``hard_block`` is True if any (boosted) weight reaches
    ``HARD_BLOCK_WEIGHT`` — a single high-confidence hit blocks on its own.

    ``boost_decoded`` raises the weight of attack signals that fired on a decoded
    representation (an attacker encoding an instruction is rare); the bare
    "encoding" observation is exempt so legitimate encoded pastes aren't punished.
    """
    product = 1.0
    hard_block = False
    for signal in signals:
        weight = signal.weight
        if (
            boost_decoded
            and signal.representation.startswith("decoded")
            and signal.attack_class != "encoding"
        ):
            weight = min(0.95, weight + _DECODED_BOOST)
        if weight >= HARD_BLOCK_WEIGHT:
            hard_block = True
        product *= 1.0 - weight
    return 1.0 - product, hard_block
