"""Supabase corpus maintenance helpers.

These utilities are intentionally offline from the guardrail hot path. They pull
review-worthy production turns into a local inbox so a human can scrub PII,
label attack classes, and promote useful cases into ``corpus/``.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path


@dataclass(frozen=True)
class SupabaseConfig:
    url: str
    service_key: str


def config_from_env() -> SupabaseConfig:
    url = (os.environ.get("PROMPTPAWS_SUPABASE_URL") or os.environ.get("SUPABASE_URL") or "").rstrip(
        "/"
    )
    key = os.environ.get("PROMPTPAWS_SUPABASE_SERVICE_KEY") or os.environ.get(
        "SUPABASE_SERVICE_KEY", ""
    )
    if not url or not key:
        raise RuntimeError("set SUPABASE_URL and SUPABASE_SERVICE_KEY")
    return SupabaseConfig(url, key)


def _request(config: SupabaseConfig, method: str, path: str, *, body=None, prefer: str | None = None):
    url = f"{config.url}/rest/v1/{path}"
    headers = {
        "apikey": config.service_key,
        "Authorization": f"Bearer {config.service_key}",
        "Content-Type": "application/json",
    }
    if prefer:
        headers["Prefer"] = prefer
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=20) as resp:
        raw = resp.read()
        return json.loads(raw) if raw else None


def _repo_root() -> Path:
    cwd = Path.cwd()
    if (cwd / "corpus").is_dir():
        return cwd
    return Path(__file__).resolve().parents[2]


def _canonical(text: str) -> str:
    return " ".join(text.lower().split())


def _load_known_texts(corpus_dir: Path, inbox_path: Path) -> set[str]:
    known: set[str] = set()
    for path in list((corpus_dir / "attacks").glob("*.json")) + list(
        (corpus_dir / "known_gaps").glob("*.json")
    ):
        try:
            rows = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        for row in rows:
            text = row.get("text")
            if isinstance(text, str):
                known.add(_canonical(text))

    if inbox_path.exists():
        try:
            rows = json.loads(inbox_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            rows = []
        for row in rows:
            text = row.get("text")
            if isinstance(text, str):
                known.add(_canonical(text))
    return known


def _interesting(row: dict, *, min_risk: float) -> bool:
    decision = row.get("decision")
    action = row.get("session_action")
    judge_score = row.get("judge_score")
    risk = float(row.get("risk_score") or 0.0)
    return (
        row.get("blocked") is True
        or decision in {"flag", "block"}
        or action in {"heighten", "refuse", "reset"}
        or risk >= min_risk
        or (isinstance(judge_score, int) and judge_score <= 3)
    )


def pull_novel_examples(
    *,
    config: SupabaseConfig | None = None,
    corpus_dir: Path | None = None,
    inbox_path: Path | None = None,
    limit: int = 200,
    min_risk: float = 0.4,
) -> int:
    """Pull review-worthy conversation rows into ``corpus/inbox/supabase_novel.json``."""
    config = config or config_from_env()
    root = _repo_root()
    corpus_dir = corpus_dir or root / "corpus"
    inbox_path = inbox_path or corpus_dir / "inbox" / "supabase_novel.json"
    inbox_path.parent.mkdir(parents=True, exist_ok=True)

    known = _load_known_texts(corpus_dir, inbox_path)
    query = urllib.parse.urlencode(
        {
            "select": (
                "id,ts,session_id,input,blocked,decision,risk_score,session_action,"
                "cumulative_risk,judge_score,judge_rationale"
            ),
            "input": "not.is.null",
            "order": "ts.desc",
            "limit": str(limit),
        }
    )
    rows = _request(config, "GET", f"conversations?{query}") or []

    existing = []
    if inbox_path.exists():
        try:
            existing = json.loads(inbox_path.read_text(encoding="utf-8"))
        except ValueError:
            existing = []

    added = 0
    for row in rows:
        text = row.get("input")
        if not isinstance(text, str) or not text.strip():
            continue
        key = _canonical(text)
        if key in known or not _interesting(row, min_risk=min_risk):
            continue
        existing.append(
            {
                "text": text,
                "class": "unknown",
                "source": f"supabase:conversations:{row.get('id')}",
                "review_status": "needs_label",
                "observed_at": row.get("ts"),
                "decision": row.get("decision"),
                "blocked": row.get("blocked"),
                "risk_score": row.get("risk_score"),
                "session_action": row.get("session_action"),
                "cumulative_risk": row.get("cumulative_risk"),
                "judge_score": row.get("judge_score"),
                "judge_rationale": row.get("judge_rationale"),
            }
        )
        known.add(key)
        added += 1

    inbox_path.write_text(json.dumps(existing, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return added


def purge_remote(
    *,
    config: SupabaseConfig | None = None,
    conversation_days: int = 90,
    session_hours: int = 24,
) -> None:
    """Delete old server-side rows after local review/export windows have passed."""
    config = config or config_from_env()
    now = datetime.now(timezone.utc)
    conv_cutoff = urllib.parse.quote(
        (now - timedelta(days=conversation_days)).isoformat(timespec="seconds")
    )
    session_cutoff = urllib.parse.quote(
        (now - timedelta(hours=session_hours)).isoformat(timespec="seconds")
    )

    _request(
        config,
        "DELETE",
        f"conversations?ts=lt.{conv_cutoff}",
        prefer="return=minimal",
    )
    _request(
        config,
        "DELETE",
        f"sessions?updated_at=lt.{session_cutoff}",
        prefer="return=minimal",
    )
