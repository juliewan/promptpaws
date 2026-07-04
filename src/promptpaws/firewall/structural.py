"""Step 5: structural detectors — the shape of an attack rather than its words.

- Fake conversation turns (many-shot): several role-labeled dialogue lines in
  one user message.
- MetaBreak (special-token / chat-template manipulation): the user injects the
  model's own special tokens (``<|start_header_id|>``, ``<|im_start|>``,
  ``[INST]``, ``<start_of_turn>`` …) so the model's parser reads the injection as
  if the system generated it, jumping the instruction/data boundary.
- Config-like authority blocks: "developer mode", "system override", markdown
  headers impersonating a role — claiming an authority the user does not have.

Reference: skills/input-firewall/references/attack-taxonomy.md.
"""

from __future__ import annotations

import re

from promptpaws.verdict import Signal

_ROLE_LINE = re.compile(r"^\s*(user|assistant|human|ai|system)\s*[:>]", re.IGNORECASE | re.MULTILINE)
_FAKE_TURN_THRESHOLD = 3

# Chat-template special tokens across model families. These delimiter shapes do
# not occur in ordinary text, so matching the literal token is high-precision.
# It is also the *right* defense: MetaBreak only works when the exact token
# string reaches the tokenizer, so an obfuscated (spaced/encoded) token stops
# being a special token and stops being an attack.
#
# Deliberately excludes bare <s>/</s> (BOS/EOS): they collide with HTML
# strikethrough and would false-positive on anyone discussing markup.
_SPECIAL_TOKEN = re.compile(
    r"<\|[^|>\n]{1,40}\|>"  # ChatML / Llama-3: <|im_start|>, <|start_header_id|>, <|eot_id|>
    r"|\[/?INST\]"  # Mistral: [INST] [/INST]
    r"|<</?SYS>>"  # Llama-2: <<SYS>> <</SYS>>
    r"|<(?:start|end)_of_turn>",  # Gemma
    re.IGNORECASE,
)

_CONFIG_AUTH = re.compile(
    r"\b(developer mode|admin mode|sudo mode|system\s*override|new\s+system\s+prompt|"
    r"role\s*:\s*system)\b"
    r"|###\s*(?:system|instruction)",  # markdown header impersonating a role
    re.IGNORECASE,
)

_METABREAK_WEIGHT = 0.85
_CONFIG_WEIGHT = 0.5
_FAKE_TURN_BASE = 0.4
_FAKE_TURN_STEP = 0.1
_FAKE_TURN_CAP = 0.85


def detect_structural(text: str, representation: str) -> list[Signal]:
    """Return structural-attack signals found in ``text``."""
    signals: list[Signal] = []

    turns = len(_ROLE_LINE.findall(text))
    if turns >= _FAKE_TURN_THRESHOLD:
        weight = min(_FAKE_TURN_CAP, _FAKE_TURN_BASE + _FAKE_TURN_STEP * (turns - _FAKE_TURN_THRESHOLD))
        signals.append(
            Signal("many_shot", f"{turns} role-labeled turns", representation, weight)
        )

    if _SPECIAL_TOKEN.search(text):
        signals.append(
            Signal("metabreak", "chat-template special token injected", representation, _METABREAK_WEIGHT)
        )

    if _CONFIG_AUTH.search(text):
        signals.append(
            Signal("policy_puppetry", "config-like authority block", representation, _CONFIG_WEIGHT)
        )

    return signals
