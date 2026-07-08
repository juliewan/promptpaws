# Test corpora

Two corpora, both first-class (Phase 1 and Phase 4 of PLANNING.md):

- `attacks/` — known attack examples per taxonomy class, used to measure catch rate.
  Every real bypass found in production becomes a new case here.
- `benign/` — benign-but-weird real messages (code snippets, base64 someone wants
  explained, foreign scripts, odd formatting), used to measure the false positive
  rate. A filter that blocks legitimate users is a failure even at 100% catch rate.

Suggested format: one JSON or YAML file per attack class / benign category, with
each case carrying the text, its class, and the expected decision.
