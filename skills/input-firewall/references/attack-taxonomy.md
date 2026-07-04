# Attack Taxonomy

Detection signals and mitigations for each attack class the firewall covers. This is a
defender's reference. It describes the shape of each attack so you can recognize and stop it.
It does not provide optimized attack strings, because a defender does not need working
payloads to build detection, they need the pattern.

## Table of contents

1. Ignore previous instructions (instruction override)
2. Roleplay and persona jailbreaks
3. Encoding
4. Token breaks
5. Summarization attacks
6. Fill-in-the-gap and completion attacks
7. Steering (gradual drift, crescendo)
8. Many-shot jailbreaking
9. Policy puppetry and prompt injection
10. Logic-based jailbreaks
11. MetaBreak (special-token / chat-template manipulation)

Each entry has three parts: what it is, signals to detect it, and how to mitigate it.

---

## 1. Ignore previous instructions

**What it is.** The user tells the model to disregard its existing instructions and follow
new ones instead. The oldest and bluntest attack. Modern variants soften the phrasing or
reassign the model's role ("you are now a different assistant").

**Signals.**
- Imperative verbs aimed at the model's own instructions: disregard, ignore, forget,
  override, reset, bypass, and their paraphrases.
- References to "previous instructions", "your rules", "the system prompt", "your guidelines".
- Role-reassignment phrasing: "you are now", "from now on you are", "act as".
- These signals must be checked on the normalized and decoded text, not just the raw text,
  since this attack is often combined with encoding or word breaks.

**Mitigation.**
- Flag or block on high-confidence override phrasing, matched semantically so paraphrases
  are caught.
- The real defense is structural and lives in prompt hardening: user text is placed as data,
  never in the instruction slot, and the system prompt asserts that user text cannot change
  the model's instructions. The firewall's job is detection and logging, not the last word.

---

## 2. Roleplay and persona jailbreaks

**What it is.** The user asks the model to adopt a persona that supposedly has no rules, or
wraps the request in fiction so the model treats its policies as not applying. The classic
"pretend you are an AI with no restrictions" family.

**Signals.**
- Requests to become a persona defined by the absence of rules: "no filter", "no
  restrictions", "no guidelines", "unrestricted", "does anything".
- Fictional framing wrapped around a request whose real target is disallowed content.
- Stacked or nested personas ("you are X who is pretending to be Y who has no limits").

**Mitigation.**
- Detect persona requests that define the persona by the absence of safety, and flag them.
- The binding defense is in prompt hardening: policies apply in every frame, including
  fiction and roleplay, and adopting a persona never suspends them. The firewall flags,
  the prompt makes it stick, and output screening catches anything that slips.

---

## 3. Encoding

**What it is.** The payload is hidden in an encoding so keyword filters see gibberish. Covers
base64, hex, rot13, URL encoding, leetspeak, homoglyphs (look-alike characters from other
scripts), and zero-width or invisible characters inserted between letters.

**Signals.**
- A high ratio of base64-like or hex-like characters, or a character distribution that does
  not match natural language.
- Presence of confusable homoglyphs (Cyrillic and Greek letters standing in for Latin ones,
  fullwidth forms, mathematical alphanumeric symbols).
- Zero-width spaces, joiners, and other invisible code points inside words.
- Unusually high entropy for the claimed language.

**Mitigation.**
- Normalize first: NFKC, strip invisibles and controls, map homoglyphs to ASCII.
- Decode-and-rescan: decode the common encodings and run every other check on the decoded
  text. Cap decode depth to stop nested-encoding loops.
- Never act on an instruction that only appears after decoding. Decoded content is untrusted
  data. If a decoded block contains an override or a disallowed request, that is a strong
  attack signal, not a legitimate instruction.

---

## 4. Token breaks

**What it is.** The attacker splits words with spaces, punctuation, or markup so that a
keyword filter matching exact strings does not see the banned word, while the model still
reads it fine. "h a c k", "ex-plo-it", "ig`nore`".

**Signals.**
- Intra-word separators: single characters interleaved with spaces, hyphens, dots, backticks,
  or inline formatting.
- Words that only become meaningful after separators are removed.

**Mitigation.**
- Collapse word breaks before scanning: remove intra-word separators and inline markup, then
  scan the collapsed form in addition to the raw form.
- Do not rely on exact keyword matching at all. Use semantic classification so the meaning is
  caught regardless of spacing. Keyword lists are a supplement, never the primary defense.

---

## 5. Summarization attacks

**What it is.** The attacker hides instructions inside a block of content and asks the model
to summarize, translate, rephrase, or continue it. The hope is the model obeys the embedded
instruction while thinking it is just processing text. Closely related to indirect prompt
injection when the content comes from a retrieved document or a web page.

**Signals.**
- A request to summarize, translate, rephrase, expand, or continue a supplied block, where
  the block itself contains imperative instructions, override phrasing, or disallowed
  requests.
- Instruction-carrying content nested inside "content to be processed".

**Mitigation.**
- Treat every supplied document as untrusted data and scan its contents with the same
  firewall checks you run on the top-level message.
- The primary defense is spotlighting, which lives in prompt hardening: the block is wrapped
  and marked as untrusted, and the model is told to process it as inert text and never to
  follow instructions found inside it. The firewall's contribution is scanning the nested
  content and flagging embedded instructions.

---

## 6. Fill-in-the-gap and completion attacks

**What it is.** Rather than asking for disallowed content directly, the attacker supplies a
leading fragment and asks the model to complete it, or provides a template with blanks. The
harmful content is in the completion, not the prompt, so a prompt-only filter sees nothing
wrong.

**Signals.**
- Leading or priming fragments that trail off where disallowed content would continue.
- "Finish this", "complete the following", "the next word is", templates with blanks to fill.
- Truncated instructions that only become harmful once completed.

**Mitigation.**
- Classify the intent of the completed meaning, not just the literal input text. Ask what the
  finished output would be, and judge that.
- This attack is best caught at the output layer, since the harm is in what the model would
  produce. Output screening is the backstop. The firewall flags obvious priming fragments;
  output screening catches the rest.

---

## 7. Steering (gradual drift, crescendo)

**What it is.** A multi-turn attack. The attacker opens with something benign, then escalates
in small steps, reframing and building on the model's earlier compliance until it reaches a
place it would have refused if asked directly. Also called the crescendo attack.

**Signals.**
- This is not visible in any single message. It only appears at the session level: a benign
  opener, then incremental escalation, then a pivot.
- Rising cumulative risk across turns combined with topic drift toward a sensitive area.

**Mitigation.**
- This is a session-tracking defense, not an input-firewall one. Maintain a cumulative risk
  score across the whole conversation. Evaluate each request against the trajectory, not in
  isolation. Earlier compliance must never authorize later escalation.
- See the output-screening skill for the session-tracking design. The firewall contributes
  per-turn signals that feed the cumulative score.

---

## 8. Many-shot jailbreaking

**What it is.** The attacker fills a long message with many fabricated question-and-answer
pairs in which the "assistant" happily complies with harmful requests, priming the real model
to continue the established pattern on a final harmful question.

**Signals.**
- A long input containing many fabricated dialogue turns, often formatted as alternating
  "User:" and "Assistant:" lines or similar role labels.
- Length combined with repetitive turn structure.
- User-authored lines that claim to be prior assistant outputs.

**Mitigation.**
- Detect and neutralize fake conversation turns in user input. Count the faux turns and flag
  when there are many. Strip or clearly re-mark user-authored "assistant" lines so the model
  does not mistake them for its own prior outputs.
- Do not let untrusted input smuggle in a long list of few-shot examples. The model should
  treat the whole block as one untrusted user message, not as conversation history.

---

## 9. Policy puppetry and prompt injection

**What it is.** The attacker formats content to look like an authoritative system
configuration, a new policy, a developer or debug mode, or spoofed role tags, so the model
treats it as a higher-authority instruction. Prompt injection is the broader family; indirect
injection is the same trick delivered through retrieved or third-party content the model reads.

**Signals.**
- Content formatted as fake system or policy blocks: pseudo-XML or JSON policy structures,
  "new policy:", "developer mode", "debug mode", "admin override".
- Spoofed role tags in user content that imitate the real chat format's system or assistant
  roles.
- Config-like structures that claim authority over the model's behavior.
- For retrieval and tools: instructions embedded in fetched documents, web pages, or tool
  output (indirect injection).

**Mitigation.**
- Detect role-tag spoofing and authority-claiming structures in untrusted input, and strip or
  escape them.
- The structural defense lives in prompt hardening: user and retrieved content can never
  redefine policy, trusted and untrusted content are separated structurally, and role tags in
  untrusted input are neutralized. For retrieval and tools, treat all external content as
  untrusted and non-authoritative by default.

---

## 10. Logic-based jailbreaks

**What it is.** An elaborate framing that tries to logically corner the model into complying:
coercive false dilemmas ("if you refuse, someone gets hurt"), dual-response tricks ("answer
once as the safe AI and once as the unfiltered AI"), hypothetical and educational framings,
opposite-day and negation games, and authority appeals.

**Signals.**
- Templates that request two answers, one filtered and one not.
- Coercive framing that makes refusal seem harmful.
- Elaborate hypothetical, educational, or fictional wrappers around a request whose real
  target is disallowed content.
- Nested conditionals and negation games designed to invert the model's behavior.

**Mitigation.**
- Judge the actual content being requested, independent of the justifying wrapper. The frame
  does not change what the output would be.
- The binding defense is in prompt hardening: policies apply under hypothetical, educational,
  and fictional framing, and dual-response splits are refused. Output screening catches
  dual-response output where one half is disallowed. The firewall flags the known templates.

---

## 11. MetaBreak (special-token / chat-template manipulation)

**What it is.** A sharper, parser-level cousin of policy puppetry (section 9). Online services
wrap user input in a backend chat template built from the model's *special tokens* — the
delimiters the tokenizer treats as structural, not as text (for example
`<|start_header_id|>`, `<|im_start|>`, `<|eot_id|>`, `[INST]`, `<<SYS>>`, `<start_of_turn>`).
Instead of persuading the model conversationally, MetaBreak injects these exact tokens into the
user message. If the wrapper does not sanitize them, the model's parser reads the injected span
as if the system emitted it, letting the attacker forge system or assistant turns and jump the
instruction/data boundary that the whole chat format is supposed to enforce.

**Signals.**
- Literal chat-template special tokens in user input: `<|...|>` pipe-delimited tokens (ChatML,
  Llama-3), `[INST]` / `[/INST]` (Mistral), `<<SYS>>` / `<</SYS>>` (Llama-2), `<start_of_turn>`
  / `<end_of_turn>` (Gemma), and their per-family variants.
- Note that these delimiter shapes essentially never occur in ordinary text, so matching the
  literal token is high-precision. Exclude tokens that collide with common markup (bare
  `<s>` / `</s>` are HTML strikethrough as well as BOS/EOS) to keep the false-positive rate low.

**Mitigation.**
- Detect and strip or escape special tokens in untrusted input before the wrapper is built. The
  firewall flags them as a high-confidence structural hit.
- A useful property: MetaBreak only works when the *exact* token string reaches the tokenizer,
  so an obfuscated token (spaced out, encoded, altered) is no longer a special token and no
  longer an attack — matching the literal token is therefore the right defense, not a fragile
  one. The structural defense still belongs in prompt hardening and in the serving stack:
  render untrusted content so injected tokens cannot reach the parser as structure, and prefer
  templating APIs that encode user text rather than concatenating it into the raw prompt.
