"""MCP server exposing promptpaws guardrails as tools.

Any MCP client — a website chat backend, an assistant app (Claude Desktop,
Claude Code, or any other MCP-capable client), or an agent framework — can
call these tools instead of importing the library. The server is a thin
adapter: all logic lives in the library modules, so in-process use and MCP
use stay behavior-identical.

Model-agnostic by default: the guardrails inspect text without calling an LLM.
Set PROMPTPAWS_OPENAI_API_KEY or OPENAI_API_KEY to enable the optional semantic
judge for ambiguous inputs; set PROMPTPAWS_POLICY too to enable output policy
judging.

Run with:  promptpaws-mcp

Transport is chosen by PROMPTPAWS_TRANSPORT (default "stdio" for local/desktop
clients; "streamable-http" or "sse" to host it as a network service a web backend
can reach). For HTTP transports, PROMPTPAWS_HOST / PROMPTPAWS_PORT set the bind
address (PORT is also honored, for PaaS hosts). Set PROMPTPAWS_LOG to a file path
to log every decision as JSON Lines, or SUPABASE_URL / SUPABASE_SERVICE_KEY to
write decision records to Supabase.

Requires the "mcp" extra:  pip install -e ".[mcp]"
"""

from __future__ import annotations

import os
from dataclasses import asdict

from mcp.server.fastmcp import FastMCP

from promptpaws.firewall import inspect as firewall_inspect
from promptpaws.hardening import harden
from promptpaws.judge import policy_judge_from_env, semantic_judge_from_env
from promptpaws.monitoring import Monitor, sink_from_env
from promptpaws.screening import screen_output as _screen_output
from promptpaws.session import SessionTracker
from promptpaws.verdict import default_refusal

_tracker = SessionTracker()

# Logging and judge layers stay opt-in. With no env vars set, this is still a
# dependency-free, rules-only server with no decision persistence.
_monitor = Monitor(sink_from_env())
_judge = semantic_judge_from_env()
_policy_judge = policy_judge_from_env()

mcp = FastMCP(
    "promptpaws",
    instructions=(
        "Guardrail layer for LLM chat interfaces. Call check_input on every "
        "user message before it reaches your model, and always forward the "
        "returned normalized_text (never the raw input)."
    ),
    host=os.environ.get("PROMPTPAWS_HOST", "127.0.0.1"),
    port=int(os.environ.get("PROMPTPAWS_PORT") or os.environ.get("PORT") or "8000"),
)


@mcp.tool()
def check_input(text: str) -> dict:
    """Inspect a user message for jailbreak/prompt-injection signals.

    Returns the firewall verdict: decision (pass | flag | block), risk_score
    (0.0-1.0), the signals that fired, and normalized_text to forward to the
    model in place of the raw input.
    """
    verdict = _monitor.firewall(firewall_inspect(text, _judge), raw_input=text)
    result = asdict(verdict)
    result["decision"] = verdict.decision.value
    return result


@mcp.tool()
def harden_prompt(
    purpose: str,
    user_message: str,
    documents: list[str] | None = None,
    policy: str | None = None,
) -> dict:
    """Build a hardened model call around an untrusted user message.

    Returns a provider-neutral system/user pair (instruction hierarchy +
    spotlighting), plus the canary strings to hand back to screen_output so it
    can detect system-prompt leakage. Place `system` and `user` in their
    respective roles — never concatenate them.
    """
    call = harden(purpose, user_message, documents=documents or (), policy=policy)
    return {
        "system": call.system,
        "user": call.user,
        "marker": call.marker,
        "canaries": list(call.canaries),
        "messages": call.messages(),
    }


@mcp.tool()
def screen_output(
    response: str,
    canaries: list[str] | None = None,
    system_prompt: str | None = None,
    refusal: str | None = None,
) -> dict:
    """Screen a model response before it reaches the user.

    Checks for system-prompt leakage (canary strings from harden_prompt, or
    verbatim spans of the system prompt) and dual-response jailbreaks. On a
    block, send `safe_response` instead of the original.
    """
    result = _monitor.screening(
        _screen_output(
            response,
            canaries=canaries or (),
            system_prompt=system_prompt,
            policy_judge=_policy_judge,
            refusal=refusal,
        ),
        response=response,
    )
    return {
        "decision": result.decision.value,
        "risk_score": result.risk_score,
        "safe_response": result.safe_response,
        "refusal": refusal if refusal is not None else default_refusal(),
        "signals": [asdict(s) for s in result.signals],
    }


@mcp.tool()
def session_risk(
    session_id: str,
    input_risk: float = 0.0,
    output_risk: float = 0.0,
    text: str | None = None,
) -> dict:
    """Fold this turn's risk into the conversation's cumulative score.

    Pass the risk_score from check_input as input_risk and from screen_output as
    output_risk. Pass the (normalized) user message as `text` to enable
    near-duplicate-rewrite detection — the fingerprint of an optimization/search
    attack that mutates one prompt many times; omit it and only the risk
    arithmetic runs. Returns the recommended action for this turn: allow, heighten
    (stricter screening), refuse, or reset (drop accumulated context). The score
    decays slowly but never resets on a benign turn — earlier compliance never
    authorizes later escalation. On a `reset` action, call session_reset to drop
    the accumulated context before the next turn.
    """
    assessment = _monitor.session(
        _tracker.record_risk(session_id, input_risk, output_risk, text=text)
    )
    return {
        "session_id": assessment.session_id,
        "turn": assessment.turn,
        "turn_risk": assessment.turn_risk,
        "cumulative_risk": assessment.cumulative_risk,
        "action": assessment.action.value,
        "signals": [asdict(s) for s in assessment.signals],
    }


@mcp.tool()
def session_reset(session_id: str) -> dict:
    """Drop a conversation's accumulated cross-turn risk.

    This is the effect of the `reset` action from session_risk: once a session
    crosses the reset threshold, clear its state so the conversation starts fresh
    instead of every later turn recommending reset forever. Safe to call for an
    unknown session id (a no-op).
    """
    _tracker.reset(session_id)
    return {"session_id": session_id, "reset": True}


def main() -> None:
    transport = os.environ.get("PROMPTPAWS_TRANSPORT", "stdio")
    mcp.run(transport=transport)


if __name__ == "__main__":
    main()
