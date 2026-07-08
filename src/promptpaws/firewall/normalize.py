"""Step 1: unicode normalization.

Defeats invisible-character and look-alike-character tricks before anything
else runs. Reference: skills/input-firewall/references/detectors.md, section 1.
"""

from __future__ import annotations

import re
import unicodedata

INVISIBLE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]")
CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# Cyrillic and Greek letters that render like Latin ones. Extend from a full
# confusables list (e.g. Unicode UTS #39 data) before production use.
CONFUSABLES = {
    "а": "a",  # Cyrillic a
    "е": "e",  # Cyrillic e
    "о": "o",  # Cyrillic o
    "р": "p",  # Cyrillic r
    "с": "c",  # Cyrillic s
    "у": "y",  # Cyrillic u
    "х": "x",  # Cyrillic kha
    "ο": "o",  # Greek omicron
    "α": "a",  # Greek alpha
}


def normalize(text: str) -> str:
    """Return the canonical scan-and-forward form of ``text``."""
    text = unicodedata.normalize("NFKC", text)
    text = INVISIBLE.sub("", text)
    text = CONTROL.sub("", text)
    return "".join(CONFUSABLES.get(ch, ch) for ch in text)
