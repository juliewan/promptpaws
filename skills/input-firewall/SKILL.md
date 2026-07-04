---
name: input-firewall
description: Build the input inspection layer for an LLM chat interface that hardens it against jailbreaks and prompt injection. Use this whenever the user wants to detect, normalize, or block adversarial user input before it reaches a model, including encoding tricks (base64, rot13, homoglyphs, zero-width characters), token breaks and split words, instruction-override attempts (ignore previous instructions), many-shot jailbreaking with fake conversation turns, policy puppetry and prompt injection with spoofed role tags, and summarization attacks that hide a payload in content to be processed. Trigger this for any request about chat guardrails, input filtering, jailbreak detection, prompt injection defense, or making a chatbot harder to abuse, even if the user does not use the word "firewall."
---

# Input Firewall

This skill builds the first defense layer for a chat interface: the code that inspects user
input before the model ever sees it. Its job is to normalize sneaky input into a plain form,
decode anything hidden, scan it for attack signals, and decide whether to block, flag, or
pass the message through.

A key idea runs through everything here: attackers win by finding the one representation of
their input that your scanner did not check. So the firewall does not scan the raw message
once. It builds several representations of the same message (raw, unicode-normalized,
decoded, word-collapsed) and scans all of them, then takes the highest risk score across all
of them. If any representation looks like an attack, the message is treated as an attack.

## Do not promise the impossible

If the user talks about making their chat "unjailbreakable," gently reset the framing before
building. No input filter is provably robust against an adaptive attacker. The realistic goal
is to stop the common automatable attacks cheaply, raise the cost of the rest, and log
everything for review. Build toward that, and say so plainly. Overclaiming here is both wrong
and a bad look for a security tool.

## The pipeline, in order

Order matters. Each step feeds the next.

1. **Normalize unicode.** Apply NFKC normalization. Strip zero-width characters and control
   characters. Map confusable homoglyphs (Cyrillic "a", fullwidth letters, mathematical
   alphanumerics) to their plain ASCII equivalents. This defeats most invisible-character and
   look-alike-character tricks on its own.
2. **Decode and rescan.** Detect common encodings and decode them, then run every later check
   on the decoded text as well. Cap decode depth (say 3 levels) so nested encodings cannot
   loop forever. Decoded content is data, never instructions.
3. **Collapse word breaks.** Remove intra-word separators and inline markup so that
   "i g n o r e", "ig-nore", and "ig`nore" all surface as "ignore" to the scanners.
4. **Scan every representation.** Run both fast rule-based signals and a semantic classifier
   over the raw, normalized, decoded, and collapsed forms. Match on meaning, not just exact
   keywords, so paraphrases do not slip through.
5. **Detect structural attacks.** Separately look for fake conversation turns (many-shot),
   spoofed role tags (policy puppetry), and config-like blocks that claim authority.
6. **Decide and log.** Combine the signals into a decision: block, flag-and-allow, or pass.
   Log the decision, the signals that fired, and which representation triggered them.

The detailed detection signals and mitigations for each of the ten attack classes live in
`references/attack-taxonomy.md`. Read it when you need the specifics for a class. Concrete
detector patterns and normalization code live in `references/detectors.md`. Read that when
you are writing the actual scanning functions.

## Detector strategy: layer by cost

Do not reach for one technique. Combine three, cheapest first:

- **Rules and regex** are fast, explainable, and strong on known patterns and structural
  tells like role tags and fake turns. They break under paraphrase.
- **Semantic classifiers** (embedding similarity to known attack templates, or a small
  trained classifier) catch reworded and novel attacks. They cost more and are fuzzier.
- **LLM-as-judge** handles the genuinely ambiguous cases as a second opinion on already
  flagged content, not on every message. Most flexible, most expensive.

Send everything through the cheap rules. Escalate only the ambiguous cases upward. This is the
same funnel logic as any high-volume detection pipeline: cast wide and cheap, then narrow with
expensive high-confidence checks.

## Guard the false positive rate

A firewall that blocks real users is a failure even if it catches every attack. Real people
send weird messages: code snippets, base64 they want explained, foreign scripts, unusual
formatting. Build a corpus of benign-but-weird messages alongside the attack corpus and track
the false positive rate against it as a first-class metric. When a rule is noisy, prefer
flag-and-allow (let it through but raise the session risk score) over an outright block.

## Output contract

The firewall should return a structured verdict, not just a boolean, so later layers and logs
can use it:

```
{
  "decision": "block" | "flag" | "pass",
  "risk_score": 0.0 to 1.0,
  "signals": [ { "class": "encoding", "detail": "base64 payload decoded", "representation": "decoded" } ],
  "normalized_text": "the cleaned text to pass forward"
}
```

Always pass `normalized_text` forward rather than the raw input, so downstream layers work on
the cleaned form. Keep the raw input only in the log.

## When to hand off to other layers

The input firewall is one of several layers. Do not try to make it do everything:

- Structural separation of trusted and untrusted content, instruction hierarchy, and
  spotlighting belong to the **prompt-hardening** skill.
- Leakage scanning, dual-response detection, and policy checks on the model's reply belong to
  the **output-screening** skill.
- Cumulative cross-turn risk and crescendo detection belong to session tracking, described in
  the output-screening skill.

If the user asks for those, point them at the relevant skill rather than cramming it here.
