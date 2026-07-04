"""Tests for the red-team harness."""

from pathlib import Path

from promptpaws.redteam import format_report, run

CORPUS = Path(__file__).resolve().parent.parent / "corpus"


def test_run_catches_all_seed_attacks_and_blocks_no_benign():
    report = run(CORPUS)
    assert report.attack_total > 0
    assert report.catch_rate == 1.0, f"bypasses: {report.misses}"
    assert report.benign_blocked == [], f"false positives: {report.benign_blocked}"
    assert report.clean


def test_per_class_totals_are_populated():
    report = run(CORPUS)
    assert report.per_class
    for _cls, (caught, total) in report.per_class.items():
        assert 0 <= caught <= total


def test_format_report_is_readable():
    text = format_report(run(CORPUS))
    assert "red-team report" in text
    assert "attacks:" in text
