"""Layer 5: monitoring.

Log every decision with the signals that fired, so attempts are visible, alerts
can fire on patterns, and real bypasses become new corpus cases (see PLANNING.md,
Layer 5). This is the layer that matters most against determined adversaries.

Local-first by design: the default sink writes JSON Lines to a local file — no
server, no network. A server-backed sink is an optional downstream consumer you
add later by swapping the sink; the emit path never changes.

Nothing here calls an LLM; it is provider-agnostic like the rest of the stack.

Security note: records retain the raw input (the skill keeps raw text only in the
log), so a log holds attack strings and possibly user PII. A local file is fine
in development; in production, access-control it and set a retention policy.
"""

from __future__ import annotations

import json
import math
import os
import urllib.error
import urllib.request
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from promptpaws.screening import ScreenResult
    from promptpaws.session import SessionAssessment
    from promptpaws.verdict import Verdict


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class DecisionRecord:
    """One logged decision from any layer."""

    ts: str
    layer: str  # "firewall" | "screening" | "session"
    decision: str
    risk_score: float
    signals: list[dict] = field(default_factory=list)
    session_id: str | None = None
    raw_input: str | None = None
    extra: dict = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False)


class MonitorSink(Protocol):
    """Destination for decision records. Swap this to change where logs go."""

    def emit(self, record: DecisionRecord) -> None: ...


class NullSink:
    """Discards records. The default for tests and library use with no logging."""

    def emit(self, record: DecisionRecord) -> None:  # noqa: D102
        return None


class MemorySink:
    """Keeps records in a list, for tests and in-process inspection."""

    def __init__(self) -> None:
        self.records: list[DecisionRecord] = []

    def emit(self, record: DecisionRecord) -> None:
        self.records.append(record)


class JsonlSink:
    """Appends one JSON object per line to a local file. The dev default."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def emit(self, record: DecisionRecord) -> None:
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(record.to_json() + "\n")


class SupabaseSink:
    """Writes decision records to a Supabase table through the REST API.

    The expected table shape is the generic ``promptpaws_decisions`` schema from
    the README: ts, layer, decision, risk_score, signals, session_id, raw_input,
    and extra. Use a service-role key server-side; never expose it to a browser.
    """

    def __init__(
        self,
        url: str,
        service_key: str,
        *,
        table: str = "promptpaws_decisions",
        timeout: float = 5.0,
    ) -> None:
        self.url = url.rstrip("/")
        self.service_key = service_key
        self.table = table
        self.timeout = timeout

    def emit(self, record: DecisionRecord) -> None:
        if not self.url or not self.service_key:
            return
        endpoint = f"{self.url}/rest/v1/{self.table}"
        body = json.dumps(asdict(record)).encode()
        req = urllib.request.Request(
            endpoint,
            data=body,
            headers={
                "apikey": self.service_key,
                "Authorization": f"Bearer {self.service_key}",
                "Content-Type": "application/json",
                "Prefer": "return=minimal",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout):
                return
        except (urllib.error.URLError, TimeoutError, ValueError):
            # Monitoring must never take the guardrail path down.
            return


def sink_from_env() -> MonitorSink:
    """Build a logging sink from environment variables.

    Precedence:
    1. Supabase when ``PROMPTPAWS_SUPABASE_URL``/``PROMPTPAWS_SUPABASE_SERVICE_KEY``
       or ``SUPABASE_URL``/``SUPABASE_SERVICE_KEY`` are set.
    2. Local JSONL when ``PROMPTPAWS_LOG`` is set.
    3. ``NullSink`` otherwise.
    """
    supabase_url = os.environ.get("PROMPTPAWS_SUPABASE_URL") or os.environ.get("SUPABASE_URL")
    service_key = os.environ.get("PROMPTPAWS_SUPABASE_SERVICE_KEY") or os.environ.get(
        "SUPABASE_SERVICE_KEY"
    )
    if supabase_url and service_key:
        table = os.environ.get("PROMPTPAWS_SUPABASE_TABLE", "promptpaws_decisions")
        return SupabaseSink(supabase_url, service_key, table=table)

    log_path = os.environ.get("PROMPTPAWS_LOG")
    if log_path:
        return JsonlSink(log_path)
    return NullSink()


def _signals(obj) -> list[dict]:
    return [asdict(s) for s in obj.signals]


class Monitor:
    """Facade that logs each layer's result and passes it through for chaining."""

    def __init__(self, sink: MonitorSink | None = None) -> None:
        self.sink = sink if sink is not None else NullSink()

    def firewall(
        self, verdict: Verdict, *, raw_input: str | None = None, session_id: str | None = None
    ) -> Verdict:
        self.sink.emit(
            DecisionRecord(
                ts=_now(),
                layer="firewall",
                decision=verdict.decision.value,
                risk_score=verdict.risk_score,
                signals=_signals(verdict),
                session_id=session_id,
                raw_input=raw_input,
                extra={"normalized_text": verdict.normalized_text},
            )
        )
        return verdict

    def screening(
        self, result: ScreenResult, *, session_id: str | None = None, response: str | None = None
    ) -> ScreenResult:
        self.sink.emit(
            DecisionRecord(
                ts=_now(),
                layer="screening",
                decision=result.decision.value,
                risk_score=result.risk_score,
                signals=_signals(result),
                session_id=session_id,
                raw_input=response,
                extra={"replaced": result.decision.value == "block"},
            )
        )
        return result

    def session(self, assessment: SessionAssessment) -> SessionAssessment:
        self.sink.emit(
            DecisionRecord(
                ts=_now(),
                layer="session",
                decision=assessment.action.value,
                risk_score=assessment.cumulative_risk,
                signals=_signals(assessment),
                session_id=assessment.session_id,
                extra={"turn": assessment.turn, "turn_risk": assessment.turn_risk},
            )
        )
        return assessment


@dataclass
class Alert:
    kind: str
    detail: str
    session_id: str | None = None


def _entropy(text: str) -> float:
    """Shannon entropy (bits/char) — a cheap proxy for encoded/random payloads."""
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def scan_alerts(
    records: list[DecisionRecord],
    *,
    repeat_threshold: int = 3,
    entropy_threshold: float = 4.5,
    min_length: int = 24,
) -> list[Alert]:
    """Surface patterns from a batch of records.

    - repeated_source: a session blocked repeatedly.
    - output_near_miss: an output-screening block (an input got past the firewall).
    - high_entropy_input: a long, high-entropy input (a possible encoded payload).
      The "novel" part of novelty detection needs a baseline this doesn't keep —
      this flags high entropy, which is the cheap half.
    """
    alerts: list[Alert] = []

    blocks_by_session: Counter[str] = Counter()
    for r in records:
        if r.layer == "firewall" and r.decision == "block" and r.session_id:
            blocks_by_session[r.session_id] += 1
    for session_id, count in blocks_by_session.items():
        if count >= repeat_threshold:
            alerts.append(
                Alert("repeated_source", f"{count} firewall blocks", session_id)
            )

    for r in records:
        if r.layer == "screening" and r.decision == "block":
            alerts.append(
                Alert("output_near_miss", "output screening blocked a response", r.session_id)
            )
        if r.layer == "firewall" and r.raw_input and len(r.raw_input) >= min_length:
            entropy = _entropy(r.raw_input)
            if entropy >= entropy_threshold:
                alerts.append(
                    Alert("high_entropy_input", f"entropy {entropy:.2f}", r.session_id)
                )

    return alerts
