"""Step 2: decode-and-rescan.

Detect likely encodings (base64, hex, URL/percent), decode them, and return
each successful decode as a new representation for the scanners. rot13 is tried
speculatively (it is its own inverse, so applying it to rot13-ciphertext yields
plaintext). Recursion is capped at MAX_DECODE_DEPTH so nested encodings cannot
loop. Decoded content is data, never instructions.

Reference: skills/input-firewall/references/detectors.md, section 2.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
from dataclasses import dataclass
from urllib.parse import unquote

MAX_DECODE_DEPTH = 3

# Long contiguous runs in each encoding's alphabet. The length floors keep
# ordinary words from being treated as encoded blobs.
BASE64_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2}){8,}")
# Percent-escapes. Like the base64/hex length floors, we require a *run* of them
# before treating text as a URL-encoded payload — otherwise a prompt that merely
# mentions percent-encoding ('"!"="%21"', a pasted link) reads as an attack.
URL_ESCAPE_RE = re.compile(r"%[0-9A-Fa-f]{2}")

_MIN_DECODED_LEN = 6
_PRINTABLE_RATIO = 0.85
_MIN_URL_ESCAPES = 4


@dataclass(frozen=True)
class Decoded:
    """A decoded representation.

    ``detected`` is True when a real encoded blob was recognized (base64/hex/
    URL) and False for a speculative transform (rot13), which should not on its
    own count as an encoding signal.
    """

    method: str
    text: str
    detected: bool


def _printable(text: str) -> bool:
    if not text:
        return False
    printable = sum(ch.isprintable() or ch in "\n\t " for ch in text)
    return printable / len(text) >= _PRINTABLE_RATIO


def _try_base64(blob: str) -> str | None:
    if len(blob) % 4 != 0:
        return None
    try:
        raw = base64.b64decode(blob, validate=True)
        text = raw.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    if len(text) < _MIN_DECODED_LEN or not _printable(text) or text == blob:
        return None
    return text


def _try_hex(blob: str) -> str | None:
    try:
        text = bytes.fromhex(blob).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    if len(text) < _MIN_DECODED_LEN or not _printable(text):
        return None
    return text


def decode_representations(text: str, _depth: int = 0) -> list[Decoded]:
    """Return decoded representations of ``text``, recursion depth-capped."""
    if _depth >= MAX_DECODE_DEPTH:
        return []

    results: list[Decoded] = []

    for match in BASE64_RE.finditer(text):
        decoded = _try_base64(match.group())
        if decoded is not None:
            results.append(Decoded("base64", decoded, True))
            results.extend(decode_representations(decoded, _depth + 1))

    for match in HEX_RE.finditer(text):
        decoded = _try_hex(match.group())
        if decoded is not None:
            results.append(Decoded("hex", decoded, True))
            results.extend(decode_representations(decoded, _depth + 1))

    if len(URL_ESCAPE_RE.findall(text)) >= _MIN_URL_ESCAPES:
        unquoted = unquote(text)
        if unquoted != text and _printable(unquoted):
            results.append(Decoded("url", unquoted, True))
            results.extend(decode_representations(unquoted, _depth + 1))

    # Speculative: only worth trying on the original text, not recursively.
    if _depth == 0:
        rot = codecs.encode(text, "rot_13")
        if rot != text:
            results.append(Decoded("rot13", rot, False))

    return results
