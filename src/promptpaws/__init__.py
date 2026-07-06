"""promptpaws: layered guardrails around an LLM chat interface.

Layers (see PLANNING.md for the full architecture):

1. Input firewall   -- ``promptpaws.firewall``   (Phase 1, done)
2. Prompt hardening -- ``promptpaws.hardening``  (Phase 2, done)
3. Output screening -- ``promptpaws.screening``  (Phase 2, done)
4. Session tracking -- ``promptpaws.session``    (Phase 3, done)
5. Monitoring       -- ``promptpaws.monitoring`` (Phase 4, done)

The red-team harness lives in ``promptpaws.redteam`` (CLI: promptpaws-redteam).
"""

from promptpaws.firewall import inspect
from promptpaws.guard import Guarded, guard
from promptpaws.judge import LLMJudge, LLMPolicyJudge
from promptpaws.hardening import ModelCall, harden
from promptpaws.monitoring import (
    DecisionRecord,
    JsonlSink,
    MemorySink,
    Monitor,
    NullSink,
    scan_alerts,
)
from promptpaws.screening import ScreenResult, screen_output
from promptpaws.session import SessionAction, SessionAssessment, SessionTracker
from promptpaws.verdict import Decision, Signal, Verdict

__all__ = [
    "Decision",
    "DecisionRecord",
    "Guarded",
    "JsonlSink",
    "LLMJudge",
    "LLMPolicyJudge",
    "MemorySink",
    "ModelCall",
    "Monitor",
    "NullSink",
    "ScreenResult",
    "SessionAction",
    "SessionAssessment",
    "SessionTracker",
    "Signal",
    "Verdict",
    "guard",
    "harden",
    "inspect",
    "scan_alerts",
    "screen_output",
]
