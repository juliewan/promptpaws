# PromptPaws planning

Last reviewed: 2026-07-11

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

Verified locally (2026-07-10, includes uncommitted working tree):

- 233 tests pass.
- 12 known gaps are tracked as expected failures.
- 41/41 attack-corpus cases are caught.
- 0/24 benign-corpus cases are blocked or flagged.

Working tree (2026-07-10, uncommitted): invisible-Unicode obfuscation detector
added to both implementations. Zero-width characters count only when placed
inside an ASCII token; bidi embedding/override/isolate controls count anywhere.
Benign controls (emoji ZWJ sequences, Persian ZWNJ) must not flag and are
tested. TypeScript port and its tests included; parity holds.

Working tree (2026-07-11, uncommitted): TS judge protocol and logging sinks
implemented, pulling items 1 and 2 of the post-publish order into the first
release (the plan allowed a provider-neutral judge in 0.1.0). `llmJudge` and
`llmPolicyJudge` take a sync-or-async `complete` callback and mirror Python's
rubric, strict parsing, LRU cache, timeout, and fail-safe. New async surface
(`inspectInputAsync`, `guardAsync`, `screenOutputAsync`) carries the
escalation funnel; sync API unchanged, parity suite still green. Monitoring
adds `Monitor` plus Null/Memory/Jsonl/Stdout sinks writing the Python
snake_case JSONL record shape, and `sinkFromEnv()` honoring `PROMPTPAWS_LOG`.
TS suite now 135 tests over ~1,450 source lines. INTEGRATION.md
stale claims fixed the same day: npm coverage statement, deployment-notes
bullet, env-var applicability, Node judge and logging examples.

TypeScript port (2026-07-08, counts updated 2026-07-10): TS0 through TS3
implemented in `packages/typescript/` (~1,500 lines, 108 tests). Live Python-parity test
compares `inspectInput` against `inspect_input` across the full shared corpus;
parity holds. TS4 pre-publish checks verified: `npm run verify` green,
`npm pack` tarball contains only LICENSE, README, dist, and package.json, and
a packed-tarball install into a clean consumer project passes JS import and
strict TS declaration checks. Package metadata (license, repository, author,
keywords, `sideEffects: false`) complete. Remaining: commit `packages/` and
`LICENSE`, then `npm publish` and verify install from the registry. Note:
`prepublishOnly` runs the parity suite, so publishing requires a machine where
`python3` can import promptpaws; this is intentional verification, not a bug.

These numbers describe the repository corpus, not production efficacy. The
benign sample is too small to support a strong false-positive claim, and the
hardening layer has not yet been benchmarked against adaptive live-model
attacks.

## Next steps (2026-07-10, updated 2026-07-11)

Sequenced by dependency, smallest shippable first.

1. Commit working tree: invisible-Unicode detector in both implementations,
   TS judge protocol, TS monitoring sinks, new async API surface, tests, doc
   updates, README image tweaks.
2. ~~Fix INTEGRATION.md before publish.~~ Done 2026-07-11: deployment-notes
   bullet no longer claims the package is Python-only, npm coverage statement
   updated, env-var applicability marked (npm reads `PROMPTPAWS_REFUSAL` and
   `PROMPTPAWS_LOG`), Node judge and logging examples added.
3. Finish TS4: commit `packages/` and `LICENSE`, `npm publish` 0.1.0, verify
   install from the registry. INTEGRATION.md and both READMEs already document
   `npm install promptpaws`, so docs describe an unpublished package until this
   lands.
4. Answer the P0 platform question: is the first deployed assistant backend
   Python or Node? Judge and logging now exist in both packages, so this no
   longer gates connects; it still decides the `SessionStore` design and where
   the monitoring flywheel's logs land.

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
semantic residue justified an LLM judge. A retest with a contextual encoder is
planned; see "P1: contextual-embedding middle tier" in the roadmap.

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

## TypeScript implementation plan

The Python API and behavior are stable enough to begin a TypeScript port. The
port will live in this repository so both implementations share the taxonomy,
corpus, documentation, and behavioral review.

### Package and runtime

- npm package: `promptpaws` (unscoped, public).
- source directory: `packages/typescript/`.
- runtime: Node.js 20 or newer.
- module format: ESM-first, with package exports and generated type declarations.
- implementation language: strict TypeScript.
- runtime dependencies: none for the deterministic core unless measurement
  demonstrates that a small dependency is safer than maintaining equivalent
  parsing or normalization code.

Proposed layout:

```text
packages/typescript/
├── package.json
├── tsconfig.json
├── src/
│   ├── firewall/
│   ├── guard.ts
│   ├── hardening.ts
│   ├── screening.ts
│   ├── session.ts
│   ├── verdict.ts
│   └── index.ts
└── test/
    ├── parity.test.ts
    └── ...
```

The Python package remains in `src/promptpaws/`; moving it is not required to
introduce the npm package.

### Compatibility contract

Python is the initial behavioral reference, but the shared corpus—not a
line-for-line translation—is the long-term specification.

For every shared fixture, both implementations must agree on:

- normalized text;
- decision (`pass`, `flag`, or `block`);
- rounded risk score;
- signal attack class, representation, and weight;
- whether a model call is constructed;
- whether output is passed through or replaced; and
- session action for equivalent turn sequences.

Signal ordering must be deterministic. Human-readable signal detail may use
language-specific wording initially, but stable rule IDs should be introduced
before consumers are encouraged to depend on individual detectors.

The TypeScript API should use idiomatic `camelCase` names while its serialized
wire form uses the existing `snake_case` contract:

```ts
inspectInput(text).riskScore
verdict.toJSON().risk_score
```

Public API parity:

| Python | TypeScript |
|---|---|
| `inspect_input` | `inspectInput` |
| `guard` | `guard` |
| `harden` | `harden` |
| `screen_output` | `screenOutput` |
| `SessionTracker` | `SessionTracker` |
| `Verdict`, `Signal`, `Decision` | matching exported types |

### Cross-language hazards to test explicitly

- Unicode NFKC behavior and control/invisible-character removal.
- JavaScript UTF-16 indexing versus Python Unicode code points.
- Base64 validation: Node's decoder is permissive by default, so detection must
  validate the alphabet, padding, UTF-8 result, and printable ratio explicitly.
- Percent decoding errors: malformed escapes must not throw out of the guard
  path.
- ROT13 behavior outside ASCII.
- Regex boundary and case-folding differences.
- Stable representation deduplication and signal order.
- Floating-point noisy-OR scoring and three-decimal rounding.
- Cryptographically secure marker/canary generation using Node's `crypto`
  module.
- Timeout, cache, and error behavior when asynchronous judges are added.

### Delivery phases

#### TS0: scaffold and contract

- Add the npm workspace/package, strict compiler configuration, formatter,
  linter, test runner, and build output.
- Define public types and JSON serialization.
- Load the existing attack, benign, and known-gap corpora from the repository.
- Add a parity-fixture generator that records expected Python results without
  executing Python from the npm package at runtime.

Gate: package builds, type-checks, and can run shared fixtures in CI.

#### TS1: deterministic input firewall

- Port verdict scoring, normalization, decoding, word collapse, rules,
  templates, anomaly detection, structural detection, and `inspectInput`.
- Preserve the same thresholds, representation names, decoded boost, and
  stacking synergy.

Gate: all attack and benign corpus cases match Python decisions and risk scores;
known gaps remain explicitly tracked rather than silently changing status.

#### TS2: guard and output path

- Port hardening, spotlight markers, canaries, `guard`, and output screening.
- Confirm system/user role separation and blocked-input short-circuiting.
- Add Python/TypeScript golden tests for model-call and screening behavior while
  ignoring intentionally random marker values.

Gate: equivalent non-random structures, signals, and replacement decisions.

#### TS3: session tracking

- Port cumulative risk, decay, crescendo, near-duplicate rewrites, LRU bounds,
  and reset behavior.
- Keep storage in-process for the first release and expose an interface that can
  later support shared stores.

Gate: equivalent actions and scores for shared multi-turn fixtures.

#### TS4: package release

- Add npm package metadata, README, license, repository links, `files` allowlist,
  exports, provenance-ready build, and a `prepublishOnly` verification command.
- Inspect the tarball with `npm pack --dry-run`.
- Install the packed tarball into a temporary consumer project and test both
  JavaScript imports and TypeScript declarations.
- Publish `0.1.0`, then verify installation from the public registry.

Gate: a clean project can run:

```bash
npm install promptpaws
```

and import the documented API without repository-relative paths.

### Deferred from the first npm release

- MCP server.
- Supabase sink and corpus helpers (local sinks shipped 2026-07-11).
- OpenAI-specific environment adapter.
- Framework-specific middleware.
- Shared Redis/database session stores.
- Streaming output screening.

These should be added after the deterministic core reaches parity. The judge
protocol was included in the first release as a provider-neutral async
callback (2026-07-11); bundled provider clients remain separate.

Proposed post-publish order (2026-07-10; items 1 and 2 landed 2026-07-11,
inside the first release as the judge-protocol clause above permits):

1. ~~**Judge protocol.**~~ Implemented 2026-07-11: `llmJudge`/`llmPolicyJudge`
   factories over a sync-or-async `complete` callback, with the Python rubrics,
   strict parsing, LRU cache, timeout, and fail-safe. Escalation funnel wired
   through `inspectInputAsync`/`guardAsync`; output judge through
   `screenOutputAsync`. Verified by ported judge unit tests plus the shared
   known-gap and benign corpora under a deterministic fake judge.
2. ~~**Sink interface.**~~ Implemented 2026-07-11: `MonitorSink.emit(record)`
   with Null/Memory/Jsonl/Stdout sinks, `Monitor` facade, `sinkFromEnv()`.
   Records serialize to the Python snake_case JSONL shape so one review
   toolchain reads logs from either backend.
3. **`SessionStore`.** Shared with the Python P1 item. Serverless Node is the
   worst case for the in-memory tracker: every cold start or scaled-out
   instance fragments conversation state. Deliberately not scaffolded as a
   sync interface now: a shared store (Redis, database) is necessarily async,
   which forces `record()` async and is an API-breaking design decision to
   make once, together with the Python abstraction, not twice.

Stays out of the TS package:

- MCP server: MCP is transport-level; the Python server already serves any
  client, including Node ones.
- Supabase sink and provider adapters: keep the zero-dependency core. Document
  custom `emit` and `complete` examples instead, as the Python docs do.

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

### P1: contextual-embedding middle tier (experiment)

Planned (2026-07-08): rerun the rejected embedding experiment with a contextual
sentence encoder instead of static vectors. Design argument until measured.

- Hypothesis: a small contextual model (bge-small or MiniLM class, ONNX, a few
  ms on CPU) separates paraphrased attacks from benign lexical overlap, the
  exact failure that disqualified `model2vec`.
- Shape: kNN distance against the embedded attack corpus, not a trained
  classifier. Each corpus entry then covers its paraphrase neighborhood, so
  corpus growth compounds detection instead of adding one string per case.
- Placement: middle gate in the escalation funnel (rules → corpus kNN → LLM
  judge). Success should also show as a reduced judge-escalation rate.
- Protocol: same split as the `model2vec` test; threshold sweep; report
  paraphrased-attack catch rate and benign false-positive rate, with dates.
  Ships only if it beats existing rules at a usable false-positive rate;
  otherwise record the numbers and keep the rejection.
- Packaging: opt-in extra behind a narrow embed callable, mirroring the judge
  protocol. Core stays dependency-free and offline. Embedded corpus vectors are
  committed so clones reproduce without downloads.

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
- Ship and maintain the TypeScript package according to the implementation plan
  above, with shared corpus parity required for every detector change.

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
- Is the first deployed backend Python or Node? Judge and logging exist in
  both; the answer now drives `SessionStore` design and log destination.
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
