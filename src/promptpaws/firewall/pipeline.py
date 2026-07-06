"""Step 6: the firewall entry point — run the pipeline, combine signals, decide.

The message is expanded into several representations (normalized, raw, collapsed,
and any decodings); every scanner runs on every representation and the signals
are combined, so an attacker cannot win by hiding in the one representation a
single scanner missed.

Decision policy (see detectors.md section 6): pass below the low threshold,
flag-and-allow between thresholds, block above the high threshold or on a single
high-confidence structural hit. Signals that fire on a decoded representation are
weighted up — legitimately encoding an instruction to the model is rare. Prefer
flag over block for a lone noisy signal to protect the false positive rate.
"""

from __future__ import annotations

from promptpaws.firewall.anomaly import detect_adversarial_noise, detect_obfuscation
from promptpaws.firewall.collapse import collapse_word_breaks
from promptpaws.firewall.decode import decode_representations
from promptpaws.firewall.normalize import normalize
from promptpaws.firewall.scan import (
    SemanticJudge,
    scan_rules,
    scan_semantic,
    scan_templates,
    should_escalate,
)
from promptpaws.firewall.structural import detect_structural
from promptpaws.verdict import Decision, Signal, Verdict, combine_signals

FLAG_THRESHOLD = 0.4
BLOCK_THRESHOLD = 0.8

_ENCODING_SIGNAL_WEIGHT = 0.3  # weight of the bare "an encoding was decoded" observation

# A single technique is often just a flag; stacking independent ones is what the
# persona-jailbreak literature shows actually drives success (persona + fictional
# framing, persona + response-prefix injection, override + fiction). When two or
# more distinct *intent* classes co-occur, add a synergy bump so a stack of
# individually flag-level signals escalates to a block.
_SYNERGY_BONUS = 0.2
# Classes that are observations, not intent, and so don't count toward a stack:
# "encoding" is a bare "something was decoded" note (already handled by the
# decoded boost), not an attack technique on its own.
_OBSERVATION_CLASSES = frozenset({"encoding"})


def inspect(text: str, judge: SemanticJudge | None = None) -> Verdict:
    """Inspect one user message and return the firewall's verdict.

    Pass an optional ``judge`` to enable the semantic layer; without one, only
    the cheap rule/structural/statistical detectors run.

    The judge is the narrow, expensive stage of the funnel: it is *not* run on
    every turn. The cheap layers score first, and only turns they leave
    ambiguous — a flag-band score, a sub-flag persona/fiction cue, or a match on
    the routing prefilter — are escalated to the judge (see
    :func:`scan.should_escalate`). This keeps the LLM cost on a small slice of
    traffic and keeps the no-judge path dependency-free.
    """
    normalized = normalize(text)
    signals: list[Signal] = []

    # Build the representations, deduping identical text so we don't count the
    # same finding twice (raw == normalized for plain ASCII, etc.).
    representations: list[tuple[str, str]] = []
    seen: set[str] = set()

    def add(name: str, value: str) -> None:
        if value not in seen:
            seen.add(value)
            representations.append((name, value))

    add("normalized", normalized)
    add("raw", text)
    add("collapsed", collapse_word_breaks(normalized))
    for decoded in decode_representations(normalized):
        if decoded.detected:
            signals.append(
                Signal(
                    "encoding",
                    f"{decoded.method} payload decoded",
                    "normalized",
                    _ENCODING_SIGNAL_WEIGHT,
                )
            )
        add(f"decoded:{decoded.method}", decoded.text)

    for name, value in representations:
        signals.extend(scan_rules(value, name))
        signals.extend(scan_templates(value, name))
        signals.extend(detect_adversarial_noise(value, name))
        signals.extend(detect_obfuscation(value, name))
        # Structural shape is scanned per representation like everything else: a
        # special token or fake-turn transcript hidden inside a base64/hex blob
        # only surfaces once it is decoded, so scanning the decoded text is what
        # catches an encoded MetaBreak. Dedup already stops identical
        # representations from being scanned twice.
        signals.extend(detect_structural(value, name))

    risk, hard_block = _score(signals)

    # Semantic escalation (the funnel's narrow end). Skip it when the cheap
    # layers already blocked — the judge could only pile onto a decided block —
    # and when no judge is configured.
    if judge is not None and not hard_block and risk < BLOCK_THRESHOLD:
        cheap_classes = {s.attack_class for s in signals}
        if risk >= FLAG_THRESHOLD or should_escalate(normalized, cheap_classes):
            semantic = scan_semantic(normalized, "normalized", judge)
            if semantic:
                signals.extend(semantic)
                risk, hard_block = _score(signals)

    decision = _decide(risk, hard_block)
    if hard_block:
        risk = max(risk, BLOCK_THRESHOLD)

    return Verdict(
        decision=decision,
        risk_score=round(risk, 3),
        normalized_text=normalized,
        signals=signals,
    )


def _score(signals: list[Signal]) -> tuple[float, bool]:
    """Combine signals into (risk, hard_block), including the stacking synergy.

    Shared so the pre- and post-escalation passes score identically.
    """
    risk, hard_block = combine_signals(signals, boost_decoded=True)
    intent_classes = {s.attack_class for s in signals if s.attack_class not in _OBSERVATION_CLASSES}
    if len(intent_classes) >= 2:
        risk = min(1.0, risk + _SYNERGY_BONUS)
    return risk, hard_block


def _decide(risk: float, hard_block: bool) -> Decision:
    if hard_block or risk >= BLOCK_THRESHOLD:
        return Decision.BLOCK
    if risk >= FLAG_THRESHOLD:
        return Decision.FLAG
    return Decision.PASS
