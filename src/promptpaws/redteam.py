"""Phase 4: the red-team harness.

Throw the taxonomy corpus at the stack and report what got through — catch rate
per attack class, and false-positive rate on the benign corpus. Every real
bypass becomes a new case in ``corpus/`` and the flywheel keeps turning.

Fully local: this is an offline runner, no server. Use it as a report during
development and as a CI gate (``main`` exits non-zero on any bypass or benign
block). ``tests/test_corpus.py`` is the pass/fail assertion form of the same idea.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

from promptpaws.firewall import inspect

# A benign message that flags (rather than blocks) still degrades a real user's
# experience and is the early warning that a detector is drifting toward
# over-blocking. Gate on it too, with a small budget so a rare edge case doesn't
# fail CI outright.
MAX_BENIGN_FLAG_RATE = 0.05


def _default_corpus_dir() -> Path:
    cwd = Path("corpus")
    if cwd.is_dir():
        return cwd
    return Path(__file__).resolve().parents[2] / "corpus"


def _load(subdir: Path) -> list[dict]:
    cases: list[dict] = []
    for path in sorted(subdir.glob("*.json")):
        cases.extend(json.loads(path.read_text()))
    return cases


@dataclass
class Report:
    attack_total: int = 0
    attack_caught: int = 0
    misses: list[tuple[str, str]] = field(default_factory=list)  # (class, text)
    benign_total: int = 0
    benign_blocked: list[str] = field(default_factory=list)
    benign_flagged: list[str] = field(default_factory=list)
    per_class: dict[str, tuple[int, int]] = field(default_factory=dict)  # class -> (caught, total)

    @property
    def catch_rate(self) -> float:
        return self.attack_caught / self.attack_total if self.attack_total else 1.0

    @property
    def block_fp_rate(self) -> float:
        return len(self.benign_blocked) / self.benign_total if self.benign_total else 0.0

    @property
    def flag_fp_rate(self) -> float:
        return len(self.benign_flagged) / self.benign_total if self.benign_total else 0.0

    @property
    def clean(self) -> bool:
        """True when every attack was caught, no benign message was blocked, and
        benign flags stay within budget."""
        return (
            not self.misses
            and not self.benign_blocked
            and self.flag_fp_rate <= MAX_BENIGN_FLAG_RATE
        )


def run(corpus_dir: Path | None = None) -> Report:
    """Run the full corpus through the firewall and tally the outcomes."""
    corpus_dir = corpus_dir or _default_corpus_dir()
    report = Report()

    per_class: dict[str, list[int]] = {}
    for case in _load(corpus_dir / "attacks"):
        cls = case.get("class", "unknown")
        caught = inspect(case["text"]).decision.value != "pass"
        report.attack_total += 1
        report.attack_caught += int(caught)
        counts = per_class.setdefault(cls, [0, 0])
        counts[0] += int(caught)
        counts[1] += 1
        if not caught:
            report.misses.append((cls, case["text"]))
    report.per_class = {k: (v[0], v[1]) for k, v in sorted(per_class.items())}

    for case in _load(corpus_dir / "benign"):
        decision = inspect(case["text"]).decision.value
        report.benign_total += 1
        if decision == "block":
            report.benign_blocked.append(case["text"])
        elif decision == "flag":
            report.benign_flagged.append(case["text"])

    return report


def format_report(report: Report) -> str:
    lines = [
        "promptpaws red-team report",
        "=" * 32,
        f"attacks: {report.attack_caught}/{report.attack_total} caught "
        f"({report.catch_rate:.0%})",
    ]
    for cls, (caught, total) in report.per_class.items():
        mark = "ok" if caught == total else "MISS"
        lines.append(f"  {cls:22} {caught}/{total}  {mark}")
    lines.append(
        f"benign:  {report.benign_total - len(report.benign_blocked)}/{report.benign_total} "
        f"passed clean of blocks (block FP rate {report.block_fp_rate:.0%}, "
        f"{len(report.benign_flagged)} flagged)"
    )
    if report.misses:
        lines.append("\nMISSED ATTACKS (bypasses — add hardened variants to the corpus):")
        lines.extend(f"  [{cls}] {text!r}" for cls, text in report.misses)
    if report.benign_blocked:
        lines.append("\nFALSE POSITIVES (benign blocked):")
        lines.extend(f"  {text!r}" for text in report.benign_blocked)
    return "\n".join(lines)


def main() -> None:
    corpus_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else None
    report = run(corpus_dir)
    print(format_report(report))
    sys.exit(0 if report.clean else 1)


if __name__ == "__main__":
    main()
