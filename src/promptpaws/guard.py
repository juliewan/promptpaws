"""Convenience facade: guard one chat turn's input, end to end.

Composes the input firewall (Layer 1) and prompt hardening (Layer 2) into a
single call and short-circuits on a block, so a chat backend wires protection in
with one function instead of orchestrating the layers by hand. The individual
layers (``inspect``, ``harden``) stay public for anyone who wants just one.

This is the *input* half of a turn. After your model responds, screen the output
with ``promptpaws.screening.screen_output`` and fold the risk into a
``SessionTracker`` — see the README, "Wire it into your chat backend".
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from promptpaws.firewall import inspect
from promptpaws.firewall.scan import SemanticJudge
from promptpaws.hardening import ModelCall, harden
from promptpaws.verdict import Decision, Verdict, default_refusal


@dataclass
class Guarded:
    """The result of guarding one turn's input.

    If ``blocked`` is True, return ``refusal`` and do not call your model.
    Otherwise send ``call.messages()`` to your model and keep ``call.canaries``
    for output screening. ``verdict`` is always the firewall result, so a
    non-blocking ``flag`` is still visible for session tracking.
    """

    verdict: Verdict
    blocked: bool
    call: ModelCall | None
    refusal: str | None


def guard(
    purpose: str,
    user_message: str,
    *,
    documents: Sequence[str] = (),
    policy: str | None = None,
    refusal: str | None = None,
    judge: SemanticJudge | None = None,
) -> Guarded:
    """Run the input firewall, then (unless it blocked) build the hardened call.

    A firewall ``block`` short-circuits: no model call is built. A ``flag`` or
    ``pass`` proceeds to hardening, using the firewall's normalized text — never
    the raw input.

    Pass an optional ``judge`` to enable the firewall's semantic layer; it is
    forwarded straight to :func:`inspect`, so the paraphrase/novel-attack backend
    works from this facade, not only from a bare ``inspect`` call.
    """
    verdict = inspect(user_message, judge)
    if verdict.decision is Decision.BLOCK:
        return Guarded(
            verdict=verdict,
            blocked=True,
            call=None,
            refusal=refusal if refusal is not None else default_refusal(),
        )
    call = harden(purpose, verdict.normalized_text, documents=documents, policy=policy)
    return Guarded(verdict=verdict, blocked=False, call=call, refusal=None)
