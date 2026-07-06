"""Tests for the red-team harness."""

from pathlib import Path

from promptpaws.redteam import MAX_BENIGN_FLAG_RATE, Report, format_report, run

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


def test_benign_flags_over_budget_fail_the_clean_gate():
    # Blocks aren't the only false positive that should fail the gate: a benign
    # message that flags degrades a real user's turn too.
    over = int(MAX_BENIGN_FLAG_RATE * 100) + 1
    report = Report(
        attack_total=1,
        attack_caught=1,
        benign_total=100,
        benign_flagged=[f"benign {i}" for i in range(over)],
    )
    assert report.flag_fp_rate > MAX_BENIGN_FLAG_RATE
    assert not report.clean

    within = Report(
        attack_total=1, attack_caught=1, benign_total=100, benign_flagged=["one weird message"]
    )
    assert within.clean
