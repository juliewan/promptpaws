"""Layer 1: the input firewall.

Pipeline order (see skills/input-firewall/SKILL.md):

1. normalize   -- NFKC, strip invisibles/controls, fold confusable homoglyphs
2. decode      -- decode-and-rescan (base64, hex, rot13, URL), depth-capped
3. collapse    -- de-obfuscate intra-word breaks into a scan-only representation
4. scan        -- rule + semantic detectors over every representation
5. structural  -- fake turns, spoofed role tags, config-like authority blocks
6. inspect     -- combine signals into a Verdict
"""

from promptpaws.firewall.pipeline import inspect

__all__ = ["inspect"]
