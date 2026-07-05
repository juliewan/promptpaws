# Planning: Chat Interface Hardening

Name: **promptpaws**

## What this is

A defense-in-depth guardrail layer that sits around an LLM chat interface. It inspects
what goes into the model, hardens how the model is instructed, and inspects what comes
back out, with session-level tracking across turns and logging for offline review.

It ships two ways:

1. As a **standalone repo** that anyone can drop around their own chat backend.
2. As the guardrail layer for **your own site's chat**, which is the first real deployment.

## What "unjailbreakable" actually means here

It does not mean provably safe. No filter or system prompt is robust against an adaptive
attacker with unlimited attempts, and anyone claiming otherwise is selling something. The
honest goal is a layered system that:

- neutralizes the common, automatable attack classes cheaply and reliably,
- forces a motivated attacker to spend real effort per attempt,
- degrades gracefully (a bypass at one layer is caught at the next), and
- logs everything so you can see attempts, learn from them, and tighten over time.

State this in the README too. It reads as credibility, not weakness, to a security audience.

## Threat model

Assets to protect:

- The system prompt and any secrets, keys, or internal context in it.
- The model's policy behavior (it should not produce disallowed content on your domain).
- Downstream tools or data the chat can reach (if any).
- Your reputation (a screenshot of your bot saying something ugly is the real damage).

Attacker profiles, in rough order of how much you'll actually see:

- **Drive-by testers**: copy-paste known jailbreaks from the internet. High volume, low
  skill. The layered defense should stop essentially all of these.
- **Tinkerers**: iterate by hand, combine techniques, encode payloads. Some will get
  through single layers. Session tracking and output screening are what catch them.
- **Determined adversaries**: adaptive, will probe your specific defenses. You will not
  stop all of these with static rules. The goal is to raise cost and detect, not to win
  every round. Monitoring is the layer that matters most here.

Out of scope for v1: model weight extraction, denial of service, and classic web app
security (auth, injection into your DB, rate limiting infra). Those matter but they are a
different repo. Note them so nobody assumes this covers them.

## Attack classes in scope

All ten map to one or more defense layers. The taxonomy reference in the input-firewall
skill has detection signals and mitigations per class.

| Attack class | Primary layer that owns the defense |
|---|---|
| Ignore previous instructions | Input firewall + prompt hardening |
| Roleplay / persona jailbreak | Prompt hardening + input firewall |
| Encoding (base64, rot13, homoglyphs, zero-width) | Input firewall (decode-and-rescan) |
| Token breaks (split words) | Input firewall (normalization) |
| Summarization attacks (payload in "content to summarize") | Prompt hardening (spotlighting) + input firewall |
| Fill-in-the-gap / completion | Output screening + prompt hardening |
| Steering (gradual drift, crescendo) | Session tracking + output screening |
| Many-shot jailbreaking | Input firewall (fake-turn detection) |
| Policy puppetry / prompt injection | Prompt hardening (structural) + input firewall |
| Logic-based jailbreaks (hypotheticals, dual response) | Prompt hardening + output screening |

## Architecture: the layers

Request flows top to bottom. A block or flag at any layer can short-circuit.

```
  user input
     |
  [1] INPUT FIREWALL      normalize, decode, scan, classify. block or flag.
     |
  [2] PROMPT HARDENING    build the model call: instruction hierarchy, data marking.
     |
  [ MODEL ]
     |
  [3] OUTPUT SCREENING    scan the response for leakage / policy violations before it ships.
     |
  [4] SESSION TRACKING    update per-conversation risk. crescendo / drift detection.
     |
  [5] MONITORING          log everything. alert on patterns. feed offline review.
     |
  response to user
```

### Layer 1: Input firewall

Runs before the model sees anything. Order matters:

1. **Unicode normalize** (NFKC), strip zero-width and control characters, map confusable
   homoglyphs to canonical forms. This defeats most homoglyph and invisible-character tricks.
2. **Decode-and-rescan**: detect and decode common encodings (base64, hex, rot13, URL,
   leetspeak), then run every downstream check on the decoded text too. Cap decode depth to
   avoid loops. Decoded content is treated as untrusted, never as instructions.
3. **De-obfuscate word breaks**: collapse intra-word separators and markup so "i g n o r e"
   and "ig-nore" both surface as "ignore" to the scanners.
4. **Scan** the normalized + decoded text with both string/regex signals and a semantic
   classifier. Match on meaning, not just keywords, so paraphrases do not slip through.
5. **Detect structural attacks**: fake conversation turns (many-shot), role-tag spoofing
   (policy puppetry), and config-like blocks claiming authority.
6. **Decide**: block, flag-and-allow, or pass clean. Log the decision with the signals.

Design note: run scanners on multiple representations (raw, normalized, decoded, collapsed)
and take the max risk. Attackers win by finding the one representation your filter did not
check.

### Layer 2: Prompt hardening

How the model call is constructed so that even input that slips past layer 1 lands as inert
data, not as instructions.

- **Instruction hierarchy**: the system prompt states plainly that user text is data to be
  processed, never instructions to be followed, and that all policies apply under every
  frame (fiction, hypothetical, "educational", roleplay, dual-response, opposite-day).
- **Spotlighting / data marking**: wrap all untrusted content (user input, retrieved docs,
  tool output) in clear delimiters and tell the model that everything inside is untrusted.
  This is the main defense against summarization and indirect-injection attacks.
- **No concatenation into the instruction slot**: user text never gets placed where the
  model reads it as part of its own directives. Keep roles clean.
- **Least context**: do not put secrets in the system prompt if you can avoid it. What is
  not there cannot leak.

### Layer 3: Output screening

The backstop. Even a perfect input filter cannot anticipate everything, so inspect the
response before the user sees it.

- Scan for policy-violating content by meaning, sized to your domain.
- Scan for **leakage**: fragments of the system prompt, secrets, or internal markers.
- Catch **dual-response** tricks where the model emitted a "safe" answer and an "unsafe"
  one side by side.
- On a hit: replace with a safe refusal, and log the near-miss loudly since it means an
  input got through.

### Layer 4: Session tracking

Single-turn defenses miss slow attacks. Track state per conversation.

- Maintain a cumulative risk score across turns. Earlier compliance never authorizes later
  escalation.
- Detect **crescendo / steering**: benign opener, incremental reframing, then the pivot.
  Watch topic drift plus rising risk.
- Evaluate each request against the conversation trajectory, not in isolation. Cross a
  threshold and you reset context or refuse.

### Layer 5: Monitoring

The layer that actually matters against determined adversaries.

- Log every decision with the triggering signals and the representation that fired.
- Alert on patterns: repeated attempts from a source, novel high-entropy inputs, near-miss
  output hits.
- Feed an offline review loop. Every real bypass becomes a new test case in the red-team
  harness and a new signal. This is the flywheel that keeps the thing current.

## Detector strategy: hybrid, not either-or

- **Rules / regex** are fast, cheap, explainable, and great for known patterns and structural
  tells (role tags, fake turns, encoding markers). They are brittle to paraphrase.
- **Semantic classifiers** (embedding similarity to known attack templates, or a small
  classifier model) catch paraphrases and novel phrasings. They cost more and are fuzzier.
- **LLM-as-judge** for the hard cases (is this steering? is this a coercive frame?). Most
  expensive, most flexible. Use as a second opinion on flagged content, not on every request.

Layer them by cost: cheap rules first, escalate the ambiguous cases up. This mirrors the
funnel pattern from detection work generally: cast wide and cheap, then narrow with
expensive high-confidence checks.

## Reference implementation targets

- **Core logic**: language-agnostic, described as clear steps so it can be ported.
- **Python**: primary reference (fits the detection tooling world, easy to unit test).
- **TypeScript / Node**: web reference so it drops into a site backend directly.

Keep the two in sync behavior-wise; the taxonomy and detector specs are the source of truth,
the language ports are just implementations.

## Build phases

**Phase 0: taxonomy and specs.** The skills. Detection signals and mitigations per attack
class, plus the layered architecture. This is the durable asset; code is downstream of it.

**Phase 1: input firewall MVP.** Normalization, decode-and-rescan, rule-based scanners,
structural detectors. Ship with a test corpus of known attacks per class.

**Phase 2: prompt hardening + output screening.** Instruction hierarchy template,
spotlighting wrapper, output leakage + policy scan.

**Phase 3: session tracking.** Cumulative risk, crescendo detection.

**Phase 4: monitoring + red-team harness.** Logging, alerting, and an automated suite that
throws the full taxonomy at the stack and reports what got through. Wire bypasses back into
the corpus.

**Phase 5: your site.** Deploy behind your own chat as the first real-traffic test.

## Success metrics

- **Catch rate** per attack class against the red-team corpus (target: near-total on the
  automatable classes).
- **False positive rate** on a corpus of benign-but-weird real messages. This is the one
  people forget. A filter that blocks legitimate users is a failure even at 100% catch rate.
- **Bypass cost**: qualitative, how many iterations a human tester needs to get through.
- **Time to new signal**: how fast a novel bypass becomes a covered case.

## Open questions for you

- Does your site's chat have any tools or data access, or is it pure conversation? Tools
  change the threat model a lot (indirect injection, tool abuse).
- What is the actual policy for your domain? "Disallowed content" has to be defined before
  output screening can check it.
- Do you want the standalone repo to be opinionated (batteries-included defaults) or a
  toolkit (compose your own)? Affects how the skills are written.
