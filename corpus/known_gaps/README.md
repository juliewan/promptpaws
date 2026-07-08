# Known-gap corpus

Attacks that the current **rule-based** layer is known to miss. They are kept
out of `attacks/` on purpose: `tests/test_corpus.py` asserts that *every* case
in `attacks/` is caught, and these are not (yet).

Instead, `tests/test_known_gaps.py` runs them as **expected failures**
(`xfail`). That makes each gap:

- **honest** — it never inflates the headline catch rate; a miss is recorded as
  a known miss, not a pass;
- **tracked** — the moment a new detector (e.g. a `SemanticJudge` behind the
  firewall) starts catching one, its `xfail` turns into an `XPASS` in the test
  report, which is the signal to promote that case into `attacks/`.

## `roleplay_paraphrase.json`

Semantically-varied paraphrases of the persona / roleplay jailbreak. The rule
layer matches literal cues ("no filter", "DAN", "unrestricted", "developer
mode"); these say the same thing without any of those tokens, plus a few that
stack a persona with fictional-scenario or response-prefix framing. They are the
acceptance test for the semantic layer.

## `in_the_wild_missed.json`

Real prompts from `TrustAIRLab/in-the-wild-jailbreak-prompts` (2023-12-25) that
the rule layer passed when the corpus was evaluated: a spoofed "OpenAI employee
debugging mode" authority claim, a leetspeak-encoded request, and a
`JOB=/ROLE=/PREFIX=` simulation frame. The caught in-the-wild prompts from the
same run live in `corpus/attacks/in_the_wild.json` — including a `PERSONA=Bob`
schema persona that graduated here once the no-rules scanner learned the
"amoral"/"uncensored" cue.

## `jailbreakv_templates.json`

Named-persona template families from `JailbreakV-28K` (mini split) that the rule
layer misses — VIOLET, the AlphaGPT/DeltaGPT dual-simulation, the good-bot/bad-bot
dual-response form, the switch-flipper, the JB/NECO personas, the fake-Linux-console
hypothetical, and the "evil confidant". They share a shape the literal scanners
don't cover: a coined character name plus an *implied* rule-drop ("without any
warning", "not required to follow any rules"), rather than a keyword like "DAN".
Payloads are sanitized to `[harmful request]` — the firewall keys on the scaffold,
not the ask. The one JailbreakV template the rule layer *does* catch (a GCG-style
optimized-suffix case caught by the structural scanner) lives in
`corpus/attacks/jailbreakv.json`. Adding "not limited to … rules/policies" to the
no-rules scanner already promoted the `Cooper` persona out of this set.
