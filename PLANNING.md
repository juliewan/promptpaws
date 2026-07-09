# PromptPaws planning

Last reviewed: 2026-07-08

## Purpose

PromptPaws is a defense-in-depth guardrail around an LLM chat interface. It:

1. inspects and normalizes user input;
2. constructs a hardened model call;
3. screens model output;
4. tracks risk across a conversation; and
5. logs decisions so real bypasses can become regression tests.

It is not an “unjailbreakable” system. The goal is to stop common automated
attacks, raise the cost of adaptive attacks, degrade safely when one layer
misses, and make failures observable.

## Current status

The Python implementation is complete for the original five-layer design:

- Input firewall: normalization, decode-and-rescan, word-break collapse,
  rules, structural detectors, anomaly detectors, representation-aware scoring,
  and stacked-attack synergy.
- Prompt hardening: instruction hierarchy, role separation, random spotlight
  markers, document wrapping, and leakage canaries.
- Output screening: canary and verbatim leakage checks, dual-response
  detection, policy-judge hook, and safe replacement responses.
- Session tracking: decayed cumulative risk, crescendo detection,
  near-duplicate rewrites, graduated actions, bounded state, and thread safety.
- Monitoring: memory, JSONL, and Supabase sinks plus basic alert scanning.
- Semantic layer: optional provider-neutral `LLMJudge` and `LLMPolicyJudge`
  implementations with routing, strict parsing, caching, timeouts, and
  fail-safe behavior.
- Interfaces: Python API, CLI, MCP server, red-team runner, and runnable backend
  example.

Verified locally:

- 228 tests pass.
- 12 known gaps are tracked as expected failures.
- 41/41 attack-corpus cases are caught.
- 0/24 benign-corpus cases are blocked or flagged.

These numbers describe the repository corpus, not production efficacy. The
benign sample is too small to support a strong false-positive claim, and the
hardening layer has not yet been benchmarked against adaptive live-model
attacks.

## Request flow

```text
user input
    |
    v
input firewall ---- block ----------------------> refusal
    |
    v
prompt hardening
    |
    v
model
    |
    v
output screening -- block ----------------------> safe replacement
    |
    v
session tracking -- heighten / refuse / reset
    |
    v
monitoring
    |
    v
response
```

A `flag` does not short-circuit the request. It allows the turn to proceed while
contributing risk to session tracking and monitoring.

## Threat model

### Assets

- The system prompt and internal context.
- The model’s domain-policy behavior.
- Downstream tools and data reachable by the chat.
- User trust and the product’s reputation.

Secrets and credentials should not be placed in model context. Leakage
detection is a backstop, not a secret-management system.

### Attackers

- Drive-by testers using published jailbreaks.
- Tinkerers combining encoding, roleplay, spoofing, and repeated rewrites.
- Adaptive attackers probing PromptPaws and the protected model.

The first group should be stopped cheaply. The second should encounter multiple
independent defenses. The third cannot be assumed stoppable by static rules;
monitoring, rate controls in the host application, and rapid regression coverage
matter most.

### In scope

- Instruction override and prompt injection.
- Persona, roleplay, hypothetical, and dual-response jailbreaks.
- Base64, hex, URL, ROT13, homoglyph, invisible-character, and token-break
  obfuscation.
- Many-shot fake conversations and chat-template token injection.
- Policy puppetry and fake authority.
- Adversarial suffixes and repeated prompt mutation.
- Indirect injection in documents or tool output.
- Multi-turn crescendo attacks.
- System-prompt leakage and domain-policy violations in output.

### Out of scope

- Model-weight extraction.
- General denial of service.
- Authentication, authorization, SQL injection, rate limiting, and other web
  application controls.
- Image-only attacks without an OCR or vision preprocessing layer.
- A guarantee against adaptive attackers with unlimited attempts.

## Design decisions

### Scan multiple representations

The firewall scans raw, normalized, collapsed, and decoded forms. An attacker
should not win by choosing the one representation a detector does not inspect.
Only normalized text is forwarded; collapsed and decoded forms are scan-only.

### Separate authority structurally

Trusted instructions stay in the system role. User messages, retrieved
documents, and tool output remain untrusted content in marked user-role blocks.
Untrusted content is never interpolated into the trusted instruction slot.

### Escalate by cost

Deterministic rules run first. An optional semantic judge sees only ambiguous
or persona-framed traffic selected by the escalation router. The default path
remains dependency-free and makes no network calls.

A static `model2vec` embedding prototype was rejected: benign lexical matches
ranked above genuinely paraphrased attacks at a usable false-positive rate.
Precise template rules handled structural families better; the remaining
semantic residue justified an LLM judge.

### Prefer explainable friction over broad blocking

One noisy signal generally flags instead of blocks. High-confidence structural
signals and independent stacked techniques block. Every result retains signal
class, detail, representation, and weight.

### Treat output hits as near misses

If output screening fires, an earlier layer failed to contain the behavior.
The original response is replaced, the event is logged, and the case should be
considered for corpus promotion.

### Keep the core provider-neutral

Judges accept a `str -> str` completion callable. Model SDKs and provider
credentials remain outside the core package.

## Roadmap

### P0: first real deployment

- Define the site assistant’s actual content policy.
- Decide whether the assistant has tools or remains conversation-only.
- Deploy the full guard → model → screen → session → monitor loop.
- Establish log access controls, PII handling, and retention.
- Review real flags, blocks, output near misses, and bypass reports.

This starts the monitoring flywheel the design depends on.

### P1: production state and observability

- Introduce a `SessionStore` abstraction with a shared Redis or database-backed
  implementation. The current tracker is process-local, so multi-worker and
  serverless deployments fragment conversation state.
- Add judge health metrics: escalation rate, latency, timeout/error rate, and
  cache-hit rate.
- Add detector fire counts and stable signal/rule identifiers.
- Add concurrency and failure-injection tests for interleaved sessions and
  degraded judge providers.

### P1: output and streaming

- Decode and rescan output representations so encoded canaries or leaked prompt
  content cannot bypass literal output checks.
- Define a streaming strategy. Current output screening requires the complete
  response. Candidate designs are buffering, holding an initial token window,
  or incremental scanning with a rolling window; each has latency and safety
  trade-offs.
- Add semantic leakage detection for paraphrased system-prompt disclosure.

### P1: evidence and corpus depth

- Grow the benign-but-weird corpus from 24 cases to at least hundreds before
  tightening thresholds.
- Add end-to-end cases for indirect injection and fill-in-the-gap/completion.
- Benchmark defended versus undefended live models on public behavior sets.
- Run an adaptive attacker with access to the implementation and report
  iterations-to-bypass.
- Measure per-layer median and p99 latency.
- Add regex fuzzing/ReDoS tests.

### P2: language coverage and tuning

- Document that the cheap lexical detectors and escalation router are primarily
  English.
- Route unsupported-language traffic to an appropriate judge or add
  language-specific rule packs.
- Replace module-level thresholds with a versioned configuration object.
- Support per-rule disabling and weight overrides without requiring a fork.

### P2: adoption

- Publish to PyPI with semantic versioning and a changelog that calls out
  verdict-changing detector updates.
- Add FastAPI/ASGI, LiteLLM/LangChain, and Vercel AI SDK integration recipes.
- Add `promptpaws report` for summaries of signals, near misses, sessions, and
  candidate corpus cases.
- Add a hosted playground that visualizes representations and signal scoring.
- Publish reproducible benchmarks and limitations.
- Add `SECURITY.md` with a private bypass-disclosure process.
- Revisit a TypeScript port after the Python configuration and storage
  interfaces stabilize.

## Success metrics

Track these separately; one headline catch rate is not sufficient.

- Catch and block rate by attack class.
- Benign block, flag, and judge-escalation rates.
- End-to-end attack success rate against live models, defended and undefended.
- Iterations or cost required for an adaptive bypass.
- Input, judge, output, and full-request latency distributions.
- Judge availability, timeout rate, and cache-hit rate.
- Output-screening near misses.
- Time from a verified bypass to a regression case and detector update.

## Open questions

- What exact policy should the first deployed assistant enforce?
- Will the assistant have tools or private data access?
- Which shared session store fits the initial deployment?
- What streaming trade-off is acceptable for the chat UX?
- Which languages must be supported by deterministic detectors?
- Should a semantic judge run inline, asynchronously over logs, or both?

## Documentation ownership

- `README.md`: product overview and quickstart.
- `INTEGRATION.md`: operational wiring, deployment shapes, and environment
  variables.
- `skills/`: durable layer-specific implementation guidance and taxonomy.
- `corpus/README.md`: corpus conventions.
- `PLANNING.md`: current decisions, risks, priorities, metrics, and open
  questions—not completed-task history or copied integration documentation.

Completed chronology remains available in git history.
