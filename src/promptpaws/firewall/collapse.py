"""Step 3: word-break collapse.

Produce a scan-only representation with intra-word separators and inline markup
removed, so "i g n o r e" and "ig-nore" surface as "ignore" to the scanners.
The model still receives the normalized text, never this form.

Two targeted transforms, chosen to avoid mangling ordinary prose:

1. Runs of single characters each followed by a separator ("i g n o r e") are
   de-spaced. A word boundary anchors the run, so "design or ecology" is left
   alone (its letters are contiguous, not single-char-separated).
2. Single separators sitting between two word characters ("ig-nore", "ig`nore")
   are removed. This also collapses benign hyphenation (scan-only, so harmless).

Reference: skills/input-firewall/references/detectors.md, section 3.
"""

from __future__ import annotations

import re

# Separators an attacker slips between characters. Includes whitespace for the
# spaced-out-letters case; excludes it for the intra-word case (removing every
# space would merge distinct words).
_RUN = re.compile(r"\b(?:\w[\s._\-*`~|]+){2,}\w\b")
_INTRA = re.compile(r"(?<=\w)[._\-*`~|](?=\w)")
_RUN_SEPS = re.compile(r"[\s._\-*`~|]+")


def collapse_word_breaks(text: str) -> str:
    """Return the de-obfuscated (scan-only) representation of ``text``."""
    text = _RUN.sub(lambda m: _RUN_SEPS.sub("", m.group()), text)
    return _INTRA.sub("", text)
