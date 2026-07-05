"""Layer 4: session tracking.

Single-turn defenses miss slow attacks. This layer carries risk across turns so
a conversation is judged by its trajectory, not one message in isolation (see
skills/output-screening/SKILL.md, "Session tracking").

Three ideas:

- **Cumulative risk.** Each turn's firewall verdict and output-screening near
  miss feed a running per-conversation score. It decays slowly but never resets
  just because a later message looks benign — earlier compliance never
  authorizes later escalation.
- **Crescendo detection.** The steering pattern is a benign opener, incremental
  reframing, then a pivot. The tell here is death-by-a-thousand-cuts: no single
  turn trips the firewall, yet the trajectory climbs. That is exactly what the
  cumulative score surfaces, plus a rising-trend check over recent turns.
- **Near-duplicate rewrites.** Optimization-style attacks (evolutionary or
  latent-diffusion search) don't type one weird prompt — they submit many small
  mutations of the *same* prompt, hunting for a phrasing that slips through. The
  final prompt can look normal; the search pattern is the tell. A cheap
  ``difflib`` similarity check over a rolling window of recent prompts catches
  the lexical-mutation case with no model call. One rephrase is normal user
  clarification, so only a *cluster* of near-identical prompts contributes risk,
  and it tops out at friction (heighten/refuse), never a lone block. Semantic
  rewrites that share meaning without sharing wording need the embedding
  ``SemanticJudge`` upstream — this catches the surface-mutation half.

When cumulative risk crosses a threshold the recommended action escalates in
steps — heighten screening, refuse, or reset the accumulated context — rather
than doing one blunt thing.

Model-agnostic: this is arithmetic over risk scores plus a string-similarity
check; it calls no LLM. Semantic topic-drift and semantic-only rewrites can be
layered on via the firewall's ``SemanticJudge`` upstream.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from enum import Enum

from promptpaws.screening import ScreenResult
from promptpaws.verdict import Signal, Verdict

HEIGHTEN_THRESHOLD = 0.4
REFUSE_THRESHOLD = 0.7
RESET_THRESHOLD = 0.9

_DECAY = 0.9  # per-turn: slow enough that a prior spike lingers for several turns
_CRESCENDO_MIN_TURNS = 3
_CRESCENDO_STEP_CAP = 0.4  # each individual turn stayed below the single-turn flag level
_CRESCENDO_RISE_FLOOR = 0.15  # a rising trend only counts once turns carry some risk

_NEAR_DUP_WINDOW = 5  # compare each prompt against this many recent prompts
_NEAR_DUP_RATIO = 0.82  # difflib similarity at/above which a prompt is "a rewrite of" another
_NEAR_DUP_MIN_HITS = 2  # one rephrase is normal; a cluster is a search
_NEAR_DUP_STEP = 0.15  # per near-duplicate neighbor
_NEAR_DUP_CAP = 0.5  # a pure-duplicate barrage reaches heighten/refuse, never a lone block

_RISING_WINDOW = 3  # turns retained for the rising-trend check (all the crescendo rule reads)
# Cap on distinct live conversations. The tracker keeps in-process state, so an
# unbounded map is a slow leak in a long-lived server; evict the least-recently-used
# once the cap is crossed. Ten thousand is generous for a single process.
_MAX_SESSIONS = 10_000


class SessionAction(str, Enum):
    ALLOW = "allow"
    HEIGHTEN = "heighten"  # apply stricter output screening this turn
    REFUSE = "refuse"  # refuse the borderline request
    RESET = "reset"  # drop the accumulated conversation context


@dataclass
class SessionState:
    session_id: str
    cumulative_risk: float = 0.0
    turn_count: int = 0
    # Running max of every turn's risk. Kept as a scalar rather than the full
    # history so the "no single turn tripped the flag" crescendo check stays exact
    # while memory stays bounded.
    max_turn_risk: float = 0.0
    recent_turn_risks: list[float] = field(default_factory=list)  # last few, for the rising-trend check
    recent_prompts: list[str] = field(default_factory=list)  # rolling window for near-dup search

    @property
    def turns(self) -> int:
        return self.turn_count


@dataclass
class SessionAssessment:
    session_id: str
    turn: int
    turn_risk: float
    cumulative_risk: float
    action: SessionAction
    signals: list[Signal] = field(default_factory=list)


def _combine(a: float, b: float) -> float:
    """Noisy-or of two independent risks."""
    return 1.0 - (1.0 - a) * (1.0 - b)


class SessionTracker:
    """In-process cumulative-risk tracker, keyed by conversation id."""

    def __init__(self, max_sessions: int = _MAX_SESSIONS) -> None:
        self._states: OrderedDict[str, SessionState] = OrderedDict()
        self._max_sessions = max_sessions

    def state(self, session_id: str) -> SessionState:
        st = self._states.get(session_id)
        if st is None:
            st = SessionState(session_id)
            self._states[session_id] = st
            while len(self._states) > self._max_sessions:
                self._states.popitem(last=False)  # evict the least-recently-used session
        else:
            self._states.move_to_end(session_id)  # touch: mark most-recently-used
        return st

    def record_risk(
        self,
        session_id: str,
        input_risk: float = 0.0,
        output_risk: float = 0.0,
        *,
        text: str | None = None,
    ) -> SessionAssessment:
        """Fold this turn's input and output risk into the session score.

        Pass ``text`` (the prompt) to enable near-duplicate-rewrite detection over
        the session's rolling window; omit it and only the risk arithmetic runs.
        """
        state = self.state(session_id)

        signals: list[Signal] = []

        # Near-duplicate search: compare against prior prompts, then remember this
        # one (bounded window). Computed before appending so we don't self-match.
        near_dup, dup_hits = self._near_duplicate(state, text)
        if text is not None:
            state.recent_prompts.append(text)
            del state.recent_prompts[:-_NEAR_DUP_WINDOW]
        if near_dup > 0.0:
            signals.append(
                Signal(
                    "near_duplicate",
                    f"{dup_hits} near-duplicate rewrites in the last {_NEAR_DUP_WINDOW} prompts",
                    "session",
                    near_dup,
                )
            )

        turn_risk = _combine(_combine(input_risk, output_risk), near_dup)
        decayed = state.cumulative_risk * _DECAY
        cumulative = _combine(decayed, turn_risk)

        state.cumulative_risk = cumulative
        state.turn_count += 1
        state.max_turn_risk = max(state.max_turn_risk, turn_risk)
        state.recent_turn_risks.append(turn_risk)
        del state.recent_turn_risks[:-_RISING_WINDOW]

        crescendo = self._is_crescendo(state)
        if crescendo:
            signals.append(
                Signal(
                    "crescendo",
                    "gradual escalation across turns",
                    "session",
                    cumulative,
                )
            )

        # Both are "each turn looks benign, the pattern doesn't" anomalies, so
        # either one escalates to at least friction even below the risk threshold.
        action = self._action(cumulative, escalate=crescendo or near_dup > 0.0)
        return SessionAssessment(
            session_id=session_id,
            turn=state.turns,
            turn_risk=round(turn_risk, 3),
            cumulative_risk=round(cumulative, 3),
            action=action,
            signals=signals,
        )

    def record(
        self,
        session_id: str,
        *,
        firewall: Verdict | None = None,
        screening: ScreenResult | None = None,
    ) -> SessionAssessment:
        """Convenience: fold a firewall verdict and/or screening result in directly."""
        input_risk = firewall.risk_score if firewall is not None else 0.0
        output_risk = screening.risk_score if screening is not None else 0.0
        text = firewall.normalized_text if firewall is not None else None
        return self.record_risk(session_id, input_risk, output_risk, text=text)

    def reset(self, session_id: str) -> None:
        """Drop a session's accumulated state (the RESET action's effect)."""
        self._states.pop(session_id, None)

    def _is_crescendo(self, state: SessionState) -> bool:
        if state.turn_count < _CRESCENDO_MIN_TURNS:
            return False
        # Death by a thousand cuts: no single turn tripped the flag, yet the
        # accumulated score is elevated. max_turn_risk is a running max, so this
        # stays exact even though only a short window of turns is retained.
        slow_climb = (
            state.cumulative_risk >= HEIGHTEN_THRESHOLD
            and state.max_turn_risk < _CRESCENDO_STEP_CAP
        )
        # Or a strictly rising trend over the last three turns.
        last = state.recent_turn_risks[-3:]
        rising = (
            len(last) == 3 and last[0] < last[1] < last[2] and last[2] > _CRESCENDO_RISE_FLOOR
        )
        return slow_climb or rising

    def _near_duplicate(self, state: SessionState, text: str | None) -> tuple[float, int]:
        """Risk weight (and neighbor count) for a prompt that is a near-duplicate
        of several recent ones — the fingerprint of an optimization/search attack.

        One rewrite is normal clarification and scores nothing; only a cluster of
        near-identical prompts contributes, and the weight is capped so a pure
        duplicate barrage can heighten or refuse but never block on its own.
        """
        if not text or not state.recent_prompts:
            return 0.0, 0
        hits = sum(
            1
            for prev in state.recent_prompts
            if SequenceMatcher(None, text, prev).ratio() >= _NEAR_DUP_RATIO
        )
        if hits < _NEAR_DUP_MIN_HITS:
            return 0.0, 0
        return min(_NEAR_DUP_CAP, _NEAR_DUP_STEP * hits), hits

    def _action(self, cumulative: float, *, escalate: bool) -> SessionAction:
        if cumulative >= RESET_THRESHOLD:
            return SessionAction.RESET
        if cumulative >= REFUSE_THRESHOLD:
            return SessionAction.REFUSE
        if cumulative >= HEIGHTEN_THRESHOLD or escalate:
            return SessionAction.HEIGHTEN
        return SessionAction.ALLOW
