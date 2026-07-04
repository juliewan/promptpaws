"""Layer 4: session tracking.

Single-turn defenses miss slow attacks. This layer carries risk across turns so
a conversation is judged by its trajectory, not one message in isolation (see
skills/output-screening/SKILL.md, "Session tracking").

Two ideas:

- **Cumulative risk.** Each turn's firewall verdict and output-screening near
  miss feed a running per-conversation score. It decays slowly but never resets
  just because a later message looks benign — earlier compliance never
  authorizes later escalation.
- **Crescendo detection.** The steering pattern is a benign opener, incremental
  reframing, then a pivot. The tell here is death-by-a-thousand-cuts: no single
  turn trips the firewall, yet the trajectory climbs. That is exactly what the
  cumulative score surfaces, plus a rising-trend check over recent turns.

When cumulative risk crosses a threshold the recommended action escalates in
steps — heighten screening, refuse, or reset the accumulated context — rather
than doing one blunt thing.

Model-agnostic: this is arithmetic over risk scores; it calls no LLM. Semantic
topic-drift can be layered on via the firewall's ``SemanticJudge`` upstream.
"""

from __future__ import annotations

from dataclasses import dataclass, field
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


class SessionAction(str, Enum):
    ALLOW = "allow"
    HEIGHTEN = "heighten"  # apply stricter output screening this turn
    REFUSE = "refuse"  # refuse the borderline request
    RESET = "reset"  # drop the accumulated conversation context


@dataclass
class SessionState:
    session_id: str
    cumulative_risk: float = 0.0
    turn_risks: list[float] = field(default_factory=list)

    @property
    def turns(self) -> int:
        return len(self.turn_risks)


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

    def __init__(self) -> None:
        self._states: dict[str, SessionState] = {}

    def state(self, session_id: str) -> SessionState:
        return self._states.setdefault(session_id, SessionState(session_id))

    def record_risk(
        self, session_id: str, input_risk: float = 0.0, output_risk: float = 0.0
    ) -> SessionAssessment:
        """Fold this turn's input and output risk into the session score."""
        state = self.state(session_id)

        turn_risk = _combine(input_risk, output_risk)
        decayed = state.cumulative_risk * _DECAY
        cumulative = _combine(decayed, turn_risk)

        state.cumulative_risk = cumulative
        state.turn_risks.append(turn_risk)

        signals: list[Signal] = []
        if self._is_crescendo(state):
            signals.append(
                Signal(
                    "crescendo",
                    "gradual escalation across turns",
                    "session",
                    cumulative,
                )
            )

        action = self._action(cumulative, crescendo=bool(signals))
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
        return self.record_risk(session_id, input_risk, output_risk)

    def reset(self, session_id: str) -> None:
        """Drop a session's accumulated state (the RESET action's effect)."""
        self._states.pop(session_id, None)

    def _is_crescendo(self, state: SessionState) -> bool:
        risks = state.turn_risks
        if len(risks) < _CRESCENDO_MIN_TURNS:
            return False
        # Death by a thousand cuts: no single turn tripped the flag, yet the
        # accumulated score is elevated.
        slow_climb = (
            state.cumulative_risk >= HEIGHTEN_THRESHOLD and max(risks) < _CRESCENDO_STEP_CAP
        )
        # Or a strictly rising trend over the last three turns.
        last = risks[-3:]
        rising = last[0] < last[1] < last[2] and last[2] > _CRESCENDO_RISE_FLOOR
        return slow_climb or rising

    def _action(self, cumulative: float, *, crescendo: bool) -> SessionAction:
        if cumulative >= RESET_THRESHOLD:
            return SessionAction.RESET
        if cumulative >= REFUSE_THRESHOLD:
            return SessionAction.REFUSE
        if cumulative >= HEIGHTEN_THRESHOLD or crescendo:
            return SessionAction.HEIGHTEN
        return SessionAction.ALLOW
