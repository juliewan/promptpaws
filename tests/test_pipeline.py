from promptpaws import Decision
from promptpaws.firewall import inspect


def test_inspect_returns_structured_verdict():
    verdict = inspect("what's the weather like?")
    assert verdict.decision is Decision.PASS
    assert verdict.risk_score == 0.0
    assert verdict.normalized_text == "what's the weather like?"
    assert verdict.signals == []


def test_inspect_forwards_normalized_text():
    verdict = inspect("hel​lo")
    assert verdict.normalized_text == "hello"
