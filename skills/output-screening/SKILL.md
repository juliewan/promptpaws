---
name: output-screening
description: Inspect a chat model's response before it reaches the user, and track risk across a whole conversation. Use this whenever the user wants a backstop that catches policy violations or leaked system-prompt content in model output, needs to detect dual-response jailbreaks where the model emits a safe and an unsafe answer together, wants to defend against completion or fill-in-the-gap attacks whose harm is in the output, or needs session-level defenses against steering and crescendo attacks that build up gradually across turns. Trigger this for any request about output filtering, response moderation, leakage detection, multi-turn or cumulative jailbreak defense, or catching what an input filter missed, even if the user does not use the word "screening."
---

# Output Screening and Session Tracking

This skill is the backstop layer and the memory layer. Two related jobs:

- **Output screening** inspects the model's response before the user sees it, because no
  input filter or system prompt catches everything, and some attacks (completion attacks,
  dual-response tricks) only show their harm in the output.
- **Session tracking** carries risk across turns, because some attacks (steering, crescendo)
  are invisible in any single message and only appear as a trajectory.

The mental model: the input firewall and prompt hardening try to prevent bad output. This
layer assumes they will sometimes fail, and verifies. A cheap check on the way out catches the
expensive mistakes.

## Output screening

Run the model's response through these checks before returning it.

### Leakage detection

Scan the response for content that should never leave: fragments of the system prompt, secret
markers, credentials, or internal context. The simplest reliable version plants a few unique
canary strings in the system prompt and blocks any response that echoes one, since a legitimate
answer never would. Combine that with similarity checks against the known system-prompt text.

### Policy violation scan

Scan the response for disallowed content, sized to the domain's policy. This is where a
completion or fill-in-the-gap attack gets caught: the input looked like a harmless fragment,
but the output is the harmful completion, and here you see the full output and can judge it.
Use the same layered detector strategy as the firewall: cheap rules first, semantic
classification for paraphrases, and an LLM judge for the ambiguous cases.

### Dual-response detection

Logic-based jailbreaks often ask for two answers side by side, one "safe" and one
"unfiltered". Detect responses that contain a refusal and a compliant answer together, or that
are split into labeled halves. If one half is disallowed, the whole response is blocked, not
just trimmed.

### On a hit

Replace the response with a safe refusal and log the event loudly. An output-screening hit is
a near miss: it means something got past the earlier layers, so it is a high-value signal for
the monitoring loop and a candidate new test for the red-team harness.

## Session tracking

Single-turn defenses miss slow attacks. Track state per conversation.

### Cumulative risk

Maintain a running risk score for each conversation. Every per-turn signal from the firewall
and every output-screening near miss feeds it. The score decays slowly but does not reset just
because a later message looks benign. The guiding rule: earlier compliance never authorizes
later escalation.

### Crescendo and drift detection

Watch for the steering pattern: a benign opener, then incremental reframing, then a pivot
toward a sensitive area. The tells are topic drift combined with rising risk over several
turns. Evaluate each new request against the conversation's trajectory, not in isolation. A
request that would be fine as an opener can be an attack as the eighth step of a slow climb.

### Response to elevated session risk

When cumulative risk crosses a threshold, escalate: apply stricter output screening, refuse
the borderline request, or reset the conversation context so the accumulated priming is
dropped. Match the response to the threshold rather than doing one blunt thing.

## Guard the false positive rate

As with the firewall, an output filter that mangles good answers is a failure. Track false
positives against a corpus of legitimate responses, especially ones that are legitimately
about sensitive topics. Prefer a clean safe refusal over a garbled or over-redacted answer.

## What this layer does not do

- Cleaning and classifying incoming input is the **input-firewall** skill.
- Building the model call and instruction hierarchy is the **prompt-hardening** skill.

This layer is the last line before the user and the memory across turns. It works best when the
earlier layers are already doing their jobs, and it exists precisely because they will
sometimes not.
