"""promptpaws: layered guardrails around an LLM chat interface.

Layers (see PLANNING.md for the full architecture):

1. Input firewall   -- ``promptpaws.firewall``   (Phase 1, done)
2. Prompt hardening -- ``promptpaws.hardening``  (Phase 2, done)
3. Output screening -- ``promptpaws.screening``  (Phase 2, done)
4. Session tracking -- ``promptpaws.session``    (Phase 3, done)
5. Monitoring       -- ``promptpaws.monitoring`` (Phase 4, done)

The red-team harness lives in ``promptpaws.redteam`` (CLI: promptpaws-redteam).
"""

from promptpaws.firewall import inspect, inspect_input
from promptpaws.guard import Guarded, guard
from promptpaws.judge import (
    LLMJudge,
    LLMPolicyJudge,
    openai_complete_from_env,
    policy_judge_from_env,
    semantic_judge_from_env,
)
from promptpaws.hardening import ModelCall, harden
from promptpaws.monitoring import (
    DecisionRecord,
    JsonlSink,
    MemorySink,
    Monitor,
    NullSink,
    SupabaseSink,
    scan_alerts,
    sink_from_env,
)
from promptpaws.screening import ScreenResult, screen_output
from promptpaws.session import SessionAction, SessionAssessment, SessionTracker
from promptpaws.verdict import Decision, Signal, Verdict, default_refusal

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
    "openai_complete_from_env",
    "policy_judge_from_env",
    "ScreenResult",
    "semantic_judge_from_env",
    "SessionAction",
    "SessionAssessment",
    "SessionTracker",
    "Signal",
    "SupabaseSink",
    "Verdict",
    "default_refusal",
    "guard",
    "harden",
    "inspect",
    "inspect_input",
    "scan_alerts",
    "screen_output",
    "sink_from_env",
]
