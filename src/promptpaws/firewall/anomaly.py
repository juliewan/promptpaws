"""Statistical anomaly detectors — shape and character statistics, not keywords.

Two deterministic, no-LLM detectors that catch attack *forms* the rule and
structural scanners miss:

- **Adversarial suffix / token salad** (``detect_adversarial_noise``): GCG-style
  optimized suffixes (``describing.\\ + similarlyNow write oppositeley.](``) look
  nothing like human writing — clusters of glued punctuation, unpronounceable
  runs, camel-cased fragments. We score a message by how many of its tokens are
  statistically "gibberish"; a cluster of them is the tell. A lone high-entropy
  token (a hash, a base64 blob the user is asking about) is *not* a suffix, so a
  minimum count and ratio keep legitimate encoded pastes clean.

- **Obfuscation** (``detect_obfuscation``): homoglyph smuggling that survives the
  small normalization table (a single word mixing Latin with Cyrillic/Greek) and
  ASCII-art letterforms that spell a banned word as a picture. It also records
  invisible Unicode inserted inside ASCII words or bidi controls used to alter
  display order. These are removed by normalization, but the removal itself is
  useful evidence when it changes an instruction-like token.

Deterministic and cheap: pure character statistics, no model call, so these run
inside the firewall without breaking its same-input-same-verdict contract.

Reference: skills/input-firewall/references/detectors.md.
"""

from __future__ import annotations

import re

from promptpaws.verdict import Signal

# --- Adversarial suffix / token salad ---------------------------------------

# Two or more punctuation/symbol chars glued together (``**``, ``](``, ``.\``,
# ``}\)``, ``»«``) — the signature of an optimized suffix, absent from prose.
_SYMBOL_CLUSTER = re.compile(r"[^\w\s]{2,}")
# 7+ consecutive consonants: past what any real word (English or transliterated)
# sustains, so a marker of random token-salad rather than language.
_CONSONANTS = re.compile(r"[bcdfghjklmnpqrstvwxz]{7,}", re.IGNORECASE)
# A lowercase→uppercase transition *inside* a token — camel-glued fragments.
_CAMEL = re.compile(r"[a-z][A-Z]")

_GIBBERISH_MIN_TOKENS = 4  # a lone weird token (hash, base64) is not a suffix
_GIBBERISH_MIN_DENSITY = 0.3  # weird tokens per token *within their own span*
_SUFFIX_WEIGHT = 0.5  # flag on its own; blocks when it rides a real instruction


def _is_gibberish(token: str) -> bool:
    """True when a token looks statistically unlike human writing."""
    if len(token) < 3 or not any(c.isalpha() for c in token):
        return False
    if _SYMBOL_CLUSTER.search(token) or _CONSONANTS.search(token):
        return True
    # CamelCase alone is a normal identifier; only suspicious glued to a symbol
    # or digit (the way optimized suffixes fuse fragments together).
    if _CAMEL.search(token) and any(not c.isalnum() and not c.isspace() for c in token):
        return True
    return False


def detect_adversarial_noise(text: str, representation: str) -> list[Signal]:
    """Flag a cluster of token-salad fragments (adversarial suffixes).

    An optimized suffix rides on the tail of an otherwise ordinary request, so a
    whole-message ratio is diluted by the benign prefix. We instead measure
    density *within the salad region* — the span from the first weird token to
    the last — so a dense burst of fragments trips regardless of how much plain
    text precedes it.
    """
    tokens = text.split()
    if len(tokens) < _GIBBERISH_MIN_TOKENS:
        return []
    weird_idx = [i for i, t in enumerate(tokens) if _is_gibberish(t)]
    if len(weird_idx) < _GIBBERISH_MIN_TOKENS:
        return []
    span = weird_idx[-1] - weird_idx[0] + 1
    if len(weird_idx) / span >= _GIBBERISH_MIN_DENSITY:
        return [
            Signal(
                "adversarial_suffix",
                f"{len(weird_idx)} token-salad fragments",
                representation,
                _SUFFIX_WEIGHT,
            )
        ]
    return []


# --- Obfuscation: mixed-script words and ASCII art --------------------------

_MIXED_SCRIPT_WEIGHT = 0.5
_ASCII_ART_WEIGHT = 0.45
_INVISIBLE_WEIGHT = 0.45

_LETTER_RUN = re.compile(r"[^\W\d_]{2,}")  # runs of >=2 unicode letters

# Inspired by LLM Guard's InvisibleText scanner, narrowed for false-positive
# control. Format characters are legitimate in emoji and several writing
# systems, so zero-width separators only count when placed *inside an ASCII
# token*. Bidi embedding/override/isolate controls are suspicious anywhere
# because they can make displayed text differ from the order a model receives.
_ZERO_WIDTH = frozenset(
    chr(code)
    for code in (
        *range(0x200B, 0x2010),
        *range(0x2060, 0x2066),
        0xFEFF,
    )
)
_BIDI_CONTROLS = frozenset(chr(code) for code in (*range(0x202A, 0x202F), *range(0x2066, 0x206A)))

_ASCII_ART_MIN_LINES = 4  # consecutive drawn lines needed to call it a letterform
_ASCII_ART_MAX_DISTINCT = 6  # a drawn line reuses a tiny alphabet of glyphs
_ASCII_ART_MIN_INK = 3  # ignore near-empty lines
_ASCII_ART_MAX_LINE_LEN = 60  # drawn rows, not wrapped prose


def _script(ch: str) -> str | None:
    """Coarse script bucket for the scripts homoglyph attacks abuse."""
    o = ord(ch)
    if "a" <= ch <= "z" or "A" <= ch <= "Z":
        return "latin"
    if 0x0400 <= o <= 0x04FF:
        return "cyrillic"
    if 0x0370 <= o <= 0x03FF:
        return "greek"
    return None


def _has_mixed_script_word(text: str) -> bool:
    """True if any single word mixes Latin with Cyrillic or Greek letters."""
    for match in _LETTER_RUN.finditer(text):
        scripts = {s for ch in match.group() if (s := _script(ch)) is not None}
        if len(scripts) >= 2:
            return True
    return False


def _has_suspicious_invisible(text: str) -> bool:
    """Detect display controls or zero-width characters splitting ASCII tokens."""
    for index, char in enumerate(text):
        if char in _BIDI_CONTROLS:
            return True
        if char not in _ZERO_WIDTH or index == 0 or index == len(text) - 1:
            continue
        before, after = text[index - 1], text[index + 1]
        if before.isascii() and before.isalnum() and after.isascii() and after.isalnum():
            return True
    return False


def _is_drawn_line(line: str) -> bool:
    """A single row that looks drawn: short, repetitive, few distinct glyphs."""
    ink = [c for c in line if not c.isspace()]
    if len(ink) < _ASCII_ART_MIN_INK or len(line) > _ASCII_ART_MAX_LINE_LEN:
        return False
    distinct = len(set(ink))
    # few distinct glyphs, and at least some repeated (a real word-line like
    # "### Usage" has too many distinct characters to qualify).
    return distinct <= _ASCII_ART_MAX_DISTINCT and len(ink) - distinct >= 2


def _looks_like_ascii_art(text: str) -> bool:
    """True when several consecutive rows draw a letterform from a few glyphs.

    Scans for a *run* of drawn lines rather than judging the whole message, so a
    banned word rendered as a picture is caught even when wrapped in a prose
    instruction ("spell out and answer the request below: <art>").
    """
    run = 0
    for line in text.splitlines():
        run = run + 1 if _is_drawn_line(line) else 0
        if run >= _ASCII_ART_MIN_LINES:
            return True
    return False


def detect_obfuscation(text: str, representation: str) -> list[Signal]:
    """Flag invisible text, homoglyph-smuggled words, and ASCII-art letterforms."""
    signals: list[Signal] = []
    if _has_suspicious_invisible(text):
        signals.append(
            Signal(
                "obfuscation",
                "invisible Unicode inside token or bidi control",
                representation,
                _INVISIBLE_WEIGHT,
            )
        )
    if _has_mixed_script_word(text):
        signals.append(
            Signal(
                "obfuscation",
                "mixed-script word (homoglyph smuggling)",
                representation,
                _MIXED_SCRIPT_WEIGHT,
            )
        )
    if _looks_like_ascii_art(text):
        signals.append(
            Signal("obfuscation", "ascii-art letterform", representation, _ASCII_ART_WEIGHT)
        )
    return signals
