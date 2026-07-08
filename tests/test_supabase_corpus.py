"""Tests for pulling production Supabase rows into the local review inbox."""

import json

from promptpaws.supabase_corpus import SupabaseConfig, pull_novel_examples, purge_remote


def test_pull_novel_examples_dedupes_existing_corpus_and_inbox(tmp_path, monkeypatch):
    corpus = tmp_path / "corpus"
    attacks = corpus / "attacks"
    inbox = corpus / "inbox" / "supabase_novel.json"
    attacks.mkdir(parents=True)
    inbox.parent.mkdir()
    (attacks / "existing.json").write_text(
        json.dumps([{"text": "ignore previous instructions", "class": "instruction_override"}])
    )
    inbox.write_text(json.dumps([{"text": "already pulled", "class": "unknown"}]))

    rows = [
        {
            "id": 1,
            "ts": "2026-07-07T00:00:00Z",
            "input": "ignore previous instructions",
            "decision": "block",
            "risk_score": 1.0,
        },
        {
            "id": 2,
            "ts": "2026-07-07T00:01:00Z",
            "input": "already pulled",
            "decision": "flag",
            "risk_score": 0.5,
        },
        {
            "id": 3,
            "ts": "2026-07-07T00:02:00Z",
            "input": "novel suspicious turn",
            "decision": "flag",
            "risk_score": 0.5,
            "session_action": "heighten",
        },
        {
            "id": 4,
            "ts": "2026-07-07T00:03:00Z",
            "input": "boring clean turn",
            "decision": "pass",
            "risk_score": 0.0,
        },
    ]

    def fake_request(_config, method, path, **_kwargs):
        assert method == "GET"
        assert path.startswith("conversations?")
        return rows

    monkeypatch.setattr("promptpaws.supabase_corpus._request", fake_request)
    added = pull_novel_examples(
        config=SupabaseConfig("https://example.supabase.co", "key"),
        corpus_dir=corpus,
        inbox_path=inbox,
    )

    pulled = json.loads(inbox.read_text())
    assert added == 1
    assert pulled[-1]["text"] == "novel suspicious turn"
    assert pulled[-1]["source"] == "supabase:conversations:3"


def test_purge_remote_deletes_old_conversations_and_sessions(monkeypatch):
    calls = []

    def fake_request(_config, method, path, **kwargs):
        calls.append((method, path, kwargs.get("prefer")))

    monkeypatch.setattr("promptpaws.supabase_corpus._request", fake_request)
    purge_remote(
        config=SupabaseConfig("https://example.supabase.co", "key"),
        conversation_days=30,
        session_hours=12,
    )

    assert len(calls) == 2
    assert calls[0][0] == "DELETE"
    assert calls[0][1].startswith("conversations?ts=lt.")
    assert calls[0][2] == "return=minimal"
    assert calls[1][1].startswith("sessions?updated_at=lt.")
