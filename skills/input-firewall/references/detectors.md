# Detectors and Normalization

Concrete building blocks for the input firewall. These are defensive detection functions.
They recognize attack shapes so the firewall can flag them. They are deliberately not a
library of working attacks.

The patterns below are illustrative starting points, not a finished ruleset. Tune the
thresholds against your own benign corpus so you do not block real users.

## Contents

1. Normalization
2. Decode-and-rescan
3. Word-break collapse
4. Structural detectors (fake turns, role tags, config blocks)
5. Semantic detection
6. Combining signals into a verdict

---

## 1. Normalization

Run every message through this before any scanning.

Steps:
- Apply NFKC unicode normalization. This folds fullwidth forms, ligatures, and many
  mathematical alphanumeric symbols back to plain characters.
- Remove zero-width and invisible code points (zero-width space, zero-width joiner and
  non-joiner, the byte-order mark, and similar).
- Strip control characters except ordinary whitespace.
- Map known confusable homoglyphs to ASCII. Maintain a small confusables table covering the
  Cyrillic and Greek letters that look like Latin ones.

Python sketch:

```python
import unicodedata
import re

INVISIBLE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]")
CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# extend this table from a full confusables list for production use
CONFUSABLES = {"\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c"}

def normalize(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = INVISIBLE.sub("", text)
    text = CONTROL.sub("", text)
    return "".join(CONFUSABLES.get(ch, ch) for ch in text)
```

TypeScript sketch:

```ts
const INVISIBLE = /[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/g;
const CONTROL = /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g;
const CONFUSABLES: Record<string, string> = {
  "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
};

export function normalize(text: string): string {
  let t = text.normalize("NFKC").replace(INVISIBLE, "").replace(CONTROL, "");
  return [...t].map((ch) => CONFUSABLES[ch] ?? ch).join("");
}
```

---

## 2. Decode-and-rescan

Detect likely encodings, decode them, and feed the decoded text back through the whole scan.
Cap the depth so nested encodings cannot loop.

Heuristics for detection:
- Base64: long runs matching the base64 alphabet, length a multiple of four, decodes to
  valid text.
- Hex: long runs of hex digits that decode to printable text.
- Rot13 and simple substitution: try the transform and see if it produces natural language.
- URL and percent encoding: presence of percent-escapes.

Design rules:
- Every successful decode produces a new representation that gets scanned by all detectors.
- Take the maximum risk across all representations.
- A decoded block that contains override phrasing or a disallowed request is a strong attack
  signal. Legitimate users rarely base64-encode an instruction to the model.
- Cap at roughly three decode levels.

---

## 3. Word-break collapse

Produce a collapsed representation where intra-word obfuscation is removed, then scan it too.

Approach:
- Remove separators that appear between single characters (spaces, hyphens, dots, backticks,
  underscores) when they sit inside what would otherwise be a word.
- Strip inline markup used to break words.
- Keep this as a separate representation. Do not overwrite the original, since normal text
  also contains hyphens and spaces and you do not want to mangle it for the model.

The point is only to give the scanners a de-obfuscated view. The model still receives the
normalized text, not the collapsed one.

---

## 4. Structural detectors

These look for the shape of an attack rather than its words.

**Fake conversation turns (many-shot).** Count lines that look like role-labeled dialogue
turns ("User:", "Assistant:", "Human:", "AI:", and close variants). A handful is normal. Many
of them in a single user message is a strong many-shot signal. Flag on a threshold and
re-mark any user-authored assistant lines so the model does not read them as its own history.

**Spoofed role tags (policy puppetry).** Look for tags or markers in user content that
imitate the real chat format's system or role delimiters, or pseudo-XML and JSON blocks that
claim to set policy. Strip or escape them so they cannot reach the model as structure.

**Config-like authority blocks.** Detect blocks that present themselves as configuration or
policy: "system:", "policy:", "developer mode", "admin", "override", wrapped in structure
that mimics settings. These claim an authority the user does not have. Flag them.

---

## 5. Semantic detection

Rules catch known shapes. Semantic detection catches paraphrases and novel phrasings.

Options, cheapest first:
- **Embedding similarity.** Keep a set of embedded reference examples for each attack class.
  Embed the incoming text (all representations) and flag when similarity to any class crosses
  a threshold. Cheap at inference time and easy to extend by adding examples.
- **Small classifier.** Train or fine-tune a small model on labeled attack and benign
  examples. More accurate, more work to maintain.
- **LLM-as-judge.** For content already flagged as ambiguous, ask a model whether the message
  is an attempt to override instructions, extract the prompt, or elicit disallowed content.
  Use it as a second opinion on flagged content, not on every request, because it is the most
  expensive path.

Match on meaning across all representations. The whole reason for normalization and decoding
is so the semantic layer sees the real message.

---

## 6. Combining signals into a verdict

Each detector returns a signal with a class, a detail, the representation that fired, and a
weight. Combine them into the verdict the firewall returns.

Suggested logic:
- Compute a risk score by combining signal weights. Do not just sum blindly; a single
  high-confidence structural hit (spoofed system tags, a decoded override) can justify a block
  on its own.
- Map the score to a decision with two thresholds: below the low threshold pass, between the
  thresholds flag-and-allow while raising session risk, above the high threshold block.
- Always return the normalized text for downstream layers and keep the raw text only in the
  log.
- Log the full signal list and which representation fired each one. This log is what feeds the
  monitoring layer and the red-team feedback loop, so it is not optional.

Prefer flag-and-allow over block for noisy single signals. A hard block should require either
high aggregate risk or one high-confidence structural hit. This keeps the false positive rate
down while still catching real attacks, since a flagged message still gets the hardened prompt,
output screening, and session tracking applied to it downstream.
