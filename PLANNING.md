# Planning: Chat Interface Hardening

Name: **promptpaws**

> **Status (2026-07-05).** Phases 0–4 are shipped and green: 162 tests passing plus
> 20 tracked known-gap xfails; red-team harness at 32/32 attacks caught across 9
> classes with 0/24 benign blocked; ruff clean. Phase 5 (first real deployment) has
> not started. See "Where things stand", "Next steps", and "Polish / refactor list"
> at the bottom — the sections above them are the durable design and still hold.

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
- **Python**: primary reference — **done**, shipped as a zero-dependency library plus an
  optional MCP server (`promptpaws-mcp`).
- **TypeScript / Node**: web reference so it drops into a site backend directly — **not
  started**; deliberately deferred until the semantic layer settles the Python API (adding
  `SemanticJudge` backends will reshape `guard()`/`inspect()` signatures, and porting twice
  is waste).

Keep the two in sync behavior-wise; the taxonomy and detector specs are the source of truth,
the language ports are just implementations.

## Where things stand

Build phases 0–4 from the original plan are complete:

- **Phase 0 — taxonomy and specs**: three skills (`input-firewall`, `prompt-hardening`,
  `output-screening`) with the attack taxonomy and detector specs in `references/`.
- **Phase 1 — input firewall**: NFKC normalization, decode-and-rescan (depth-capped),
  word-break collapse, rule scanners, structural detectors (many-shot, MetaBreak,
  policy puppetry), statistical anomaly detectors (adversarial suffix, mixed-script and
  ASCII-art obfuscation), scored across representations with a stacking synergy bump.
- **Phase 2 — prompt hardening + output screening**: instruction hierarchy, per-request
  spotlight markers, canary tripwires; leakage/verbatim-span/dual-response screening.
- **Phase 3 — session tracking**: cumulative decayed risk, crescendo detection,
  near-duplicate-rewrite detection, graduated allow/heighten/refuse/reset actions.
- **Phase 4 — monitoring + red-team harness**: pluggable sinks (JSONL default),
  `scan_alerts`, `promptpaws-redteam` reporting catch/FP rates with a non-zero exit on
  any bypass or benign block.

Shipped beyond the original plan:

- **`guard()` facade** — firewall + hardening in one call, the recommended integration.
- **MCP server** — stdio/HTTP transports, four tools, env-var logging.
- **Known-gaps machinery** — `corpus/known_gaps/` runs as xfail so misses are recorded,
  never counted as passes; an XPASS is the promotion signal into `corpus/attacks/`.
- **External dataset evaluation** — JBB-Behaviors benign split: 0% false blocks;
  JailbreakV-28K text templates: 78% caught (the remaining ~8 named-persona families are
  tracked known gaps). Testing earned one new production rule (rule-negation cue).

What exists only as a hook: `SemanticJudge` (firewall) and `PolicyJudge` (screening) are
Protocols with no implementation behind them. Everything currently caught is caught by
rules, structure, or statistics.

## Next steps (priority order)

1. **Semantic layer v1 — the highest-value item in the repo.** Implement the first
   `SemanticJudge` backend: embedding similarity against the attack corpus + known-gap
   templates, shipped as an optional extra (`pip install promptpaws[semantic]`) using a
   small local embedding model so the core stays zero-dependency and provider-free. The
   20 xfail cases are the ready-made acceptance test: success is xfails flipping to
   XPASS and being promoted into `corpus/attacks/`. This is also the unlock for the
   README's known limitation — crescendo detection needs a semantic layer to feed
   per-turn risk for keyword-clean escalation. A first `PolicyJudge` backend can follow
   the same pattern.
2. ~~**CI.**~~ **Done** — `.github/workflows/ci.yml` runs ruff + pytest +
   `promptpaws-redteam` on 3.10 and 3.12, so the red-team harness now genuinely gates
   as the README claims.
3. **Phase 5 — deploy behind the site chat.** The README's Vercel path is written but
   unexercised; deploying it is what starts the monitoring flywheel (real bypasses →
   corpus → new signals), which the whole design says is the layer that matters most.
   Prerequisites that fall out of this: define the site's actual content policy (the
   `policy=` string), and decide tools/no-tools (still pure conversation as planned).
4. **Corpus depth.** Two in-scope taxonomy classes have no corpus file at all:
   summarization/indirect injection and fill-in-the-gap/completion (they're covered by
   hardening/screening design, but nothing regression-tests them end to end). The benign
   corpus is 24 cases — thin for the metric the plan itself calls the one people forget;
   grow it toward 100+ benign-but-weird messages (translation requests, markup
   discussions, fiction asks, "ignore my typo" phrasing) before tightening any weights.
5. **TypeScript port** — stays deferred behind 1–3 (see above).

## Polish / refactor list

Concrete trouble spots found in review, roughly ordered by real-world impact.
**Resolved** (commit `ci-and-session-hardening`):

- ~~**`SessionTracker` grows without bound**~~ — LRU eviction caps live sessions
  (`_MAX_SESSIONS`), `turn_risks` is replaced by a running `max_turn_risk` plus a
  3-turn window, so per-session memory is bounded and crescendo detection is unchanged.
- ~~**MCP sessions can't be reset**~~ — added a `session_reset` tool.
- ~~**Near-duplicate detection is unreachable over MCP**~~ — `session_risk` now takes an
  optional `text` param threaded into `record_risk`.
- ~~**`.gitignore` missing `venv/`**~~ — added.

**Also resolved** (commit `firewall-depth-and-semantic-prep`):

- ~~**`guard()` has no `judge` passthrough**~~ — `guard()` now takes a `judge` and
  forwards it to `inspect()`, so the semantic backend works from the flagship entry
  point. (A `Monitor` passthrough was considered and dropped: guard returns the verdict,
  so the caller logs it directly — no need to thread a sink through the facade.)
- ~~**Structural detection only saw the normalized text**~~ — `detect_structural` now
  runs per representation, so a base64-wrapped MetaBreak token is caught on its decoded
  form. Locked in by a new corpus case and a targeted pipeline test (catch rate 33/33).
- ~~**Red-team `clean` ignored benign flags**~~ — added `flag_fp_rate` and a
  `MAX_BENIGN_FLAG_RATE` (5%) budget folded into the `clean` gate.
- ~~**Duplicate refusal constants**~~ — single-sourced as `verdict.SAFE_REFUSAL`;
  `screening` and `guard` both reference it.
- ~~**`scan_alerts` recomputed entropy twice**~~ — computed once, reused.

The polish list is now clear except for the semantic-layer work itself, which is
next-steps item 1, not a cleanup.

## Success metrics

Targets from the original plan, with current measurements:

- **Catch rate** per attack class against the red-team corpus (target: near-total on the
  automatable classes). *Now: 100% on the 32-case literal corpus across 9 classes; 78%
  on JailbreakV-28K text templates; 20 known-gap paraphrase/persona cases tracked as
  xfail rather than counted.*
- **False positive rate** on a corpus of benign-but-weird real messages. This is the one
  people forget. A filter that blocks legitimate users is a failure even at 100% catch
  rate. *Now: 0% blocks and 0% flags on 24 benign cases — but the corpus is too small to
  trust; growing it is next-steps item 4.*
- **Bypass cost**: qualitative, how many iterations a human tester needs to get through.
  *Not yet measured; becomes measurable once Phase 5 traffic exists.*
- **Time to new signal**: how fast a novel bypass becomes a covered case. *The loop
  works — the JailbreakV rule-negation cue went eval-miss → detector → promoted catch —
  but it isn't yet timed against real traffic.*

## Open questions

Two of the original three are resolved:

- ~~Opinionated or toolkit?~~ **Both, and it works**: layers stay public (`inspect`,
  `harden`, `screen_output`), `guard()` is the batteries-included path, MCP wraps it all.
- ~~What is the policy for your domain?~~ **Structurally answered** — `policy=` and the
  pluggable `PolicyJudge` keep the core policy-free — but the *actual* site policy text
  still needs writing as part of Phase 5.
- **Still open:** does the site chat get tools or data access, or stay pure
  conversation? Tools change the threat model a lot (indirect injection, tool abuse);
  everything so far assumes pure conversation.
