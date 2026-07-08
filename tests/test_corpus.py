"""Catch-rate and false-positive-rate checks against the corpora.

The contract is deliberately loose so weight tuning doesn't make it brittle:
every attack must be caught (flag or block, never pass), and every benign
message must pass. Tighten to exact decisions per class as the corpora grow.
"""

import json
from pathlib import Path

import pytest

from promptpaws.firewall import inspect

CORPUS = Path(__file__).resolve().parent.parent / "corpus"


def _load(subdir: str) -> list[dict]:
    cases: list[dict] = []
    for path in sorted((CORPUS / subdir).glob("*.json")):
        cases.extend(json.loads(path.read_text()))
    return cases


ATTACKS = _load("attacks")
BENIGN = _load("benign")


@pytest.mark.parametrize("case", ATTACKS, ids=lambda c: f"{c['class']}:{c['text'][:30]}")
def test_attacks_are_caught(case):
    verdict = inspect(case["text"])
    assert verdict.decision.value in {"flag", "block"}, (
        f"missed {case['class']} attack: {case['text']!r} -> {verdict.decision.value}"
    )


@pytest.mark.parametrize("case", BENIGN, ids=lambda c: c["text"][:30])
def test_benign_passes(case):
    verdict = inspect(case["text"])
    assert verdict.decision.value == "pass", (
        f"false positive on benign: {case['text']!r} -> {verdict.decision.value} "
        f"({[s.attack_class for s in verdict.signals]})"
    )
