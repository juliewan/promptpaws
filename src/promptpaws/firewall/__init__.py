"""Layer 1: the input firewall.

Pipeline order (see skills/input-firewall/SKILL.md):

1. normalize   -- NFKC, strip invisibles/controls, fold confusable homoglyphs
2. decode      -- decode-and-rescan (base64, hex, rot13, URL), depth-capped
3. collapse    -- de-obfuscate intra-word breaks into a scan-only representation
4. scan        -- rule + semantic detectors over every representation
5. structural  -- fake turns, spoofed role tags, config-like authority blocks
6. inspect     -- combine signals into a Verdict
"""

from promptpaws.firewall.pipeline import inspect as inspect_input

# ``inspect`` also names a stdlib module; ``inspect_input`` is the documented
# name and this is a compatibility alias for existing callers.
inspect = inspect_input

__all__ = ["inspect", "inspect_input"]
