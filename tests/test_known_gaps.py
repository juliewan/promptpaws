"""Acceptance tests for attacks the rule-based layer is known to miss.

These are paraphrased/stacked attacks that the literal rule scanners do not
catch. They are marked ``xfail`` so a miss is the *expected* outcome today
without breaking CI, and a future detector that catches one shows up as an
``XPASS`` — the cue to promote that case into ``corpus/attacks/``.

See ``corpus/known_gaps/README.md``.
"""

import json
from pathlib import Path

import pytest

from promptpaws.firewall import inspect

KNOWN_GAPS = Path(__file__).resolve().parent.parent / "corpus" / "known_gaps"


def _load() -> list[dict]:
    cases: list[dict] = []
    for path in sorted(KNOWN_GAPS.glob("*.json")):
        cases.extend(json.loads(path.read_text()))
    return cases


GAP_CASES = _load()


@pytest.mark.xfail(
    reason="rule layer misses paraphrased/stacked personas; needs the semantic layer",
    strict=False,
)
@pytest.mark.parametrize(
    "case", GAP_CASES, ids=lambda c: f"{c.get('variant', c['class'])}:{c['text'][:30]}"
)
def test_paraphrased_attacks_are_caught(case):
    verdict = inspect(case["text"])
    assert verdict.decision.value in {"flag", "block"}, (
        f"still missed: {case['text']!r} -> {verdict.decision.value}"
    )
