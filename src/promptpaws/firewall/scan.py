"""Step 4: rule-based and semantic scanners.

Run over every representation (raw, normalized, decoded, collapsed); the
pipeline combines the signals with a noisy-or. Rules are cheap and explainable;
the semantic scanner is a pluggable escalation hook for paraphrases.

Match on word boundaries so a keyword reconstituted by the collapse step (e.g.
"i g n o r e" -> "ignore") is caught, while substrings of longer words are not.

Reference: skills/input-firewall/references/detectors.md, sections 4-5.
"""

from __future__ import annotations

import re
from typing import Protocol

from promptpaws.verdict import Signal

# Instruction override: an override verb near an instruction-like target.
_OVERRIDE = re.compile(
    r"\b(ignore|disregard|forget|override|bypass|reset|discard)\b"
    r"[^.\n]{0,40}?"
    r"\b(instructions?|rules?|guidelines?|directives?|constraints?|prompt|"
    r"system\s*prompt)\b",
    re.IGNORECASE,
)

# Role reassignment. Kept narrow ("...now", or "act as" an unrestricted persona)
# so ordinary "act as a translator" requests do not trip it.
_ROLE_REASSIGN = re.compile(
    r"\b(you are now|from now on,?\s+you are|you are no longer|you will now\b|"
    r"act as (?:an?\s+)?(?:unrestricted|unfiltered|jailbroken|ai|assistant|model)|"
    r"pretend (?:to be|you are))\b",
    re.IGNORECASE,
)

# Roleplay / no-rules persona.
_NO_RULES = re.compile(
    r"\b(no (?:filter|restrictions?|rules?|guidelines?|limits?|constraints?)|"
    r"without (?:any )?(?:restrictions?|filters?|rules?)|unrestricted|unfiltered|"
    r"uncensored|amoral|jailbro?ken|do anything now|dan|opposite day|developer mode|"
    # "not limited to OpenAI's rules and policies" — a rule-negation the plain
    # "no rules" alternatives miss. Attack-only; the bounded gap lets a possessive
    # or "any" sit between the verb and its target.
    r"not (?:limited|bound|restricted|subject) (?:to|by)[^.\n]{0,30}"
    r"(?:rules?|policies|policy|guidelines?|restrictions?|ethics?|morals?))\b",
    re.IGNORECASE,
)

# Fictional / hypothetical scenario framing. Benign on its own — real story and
# thought-experiment requests use exactly this language — so the weight is low
# and alone it stays below the flag line. It matters as the *partner* half the
# persona-jailbreak literature shows makes a persona effective: stacked with a
# persona or override, the pipeline's synergy bump escalates the pair to a block.
_HYPOTHETICAL = re.compile(
    r"\b(in (?:this|a) (?:fictional|hypothetical|imaginary|make-believe) "
    r"(?:world|scenario|setting|story|universe)|"
    r"hypothetically(?: speaking)?|"
    r"let'?s (?:write|imagine|pretend)|"
    r"imagine (?:a world|a scenario|that you are)|"
    r"for (?:this|a) (?:story|novel|screenplay|roleplay|thought experiment))\b",
    re.IGNORECASE,
)

# Response-prefix injection: dictating the opening tokens of the reply to strand
# the model past its own refusal ("begin your reply with 'Sure, here is...'").
# Narrowed to an explicit compliance opener so benign "start with a summary"
# formatting requests do not trip it.
_PREFIX_INJECT = re.compile(
    r"\b(?:begin|start)\b[^.\n]{0,25}\b(?:reply|response|answer|output)\b"
    r"[^.\n]{0,15}\bwith\b\s*['\"]?"
    r"(?:sure|of course|certainly|absolutely|here'?s|here is)\b",
    re.IGNORECASE,
)

_OVERRIDE_WEIGHT = 0.5
_ROLE_WEIGHT = 0.45
_NO_RULES_WEIGHT = 0.5
_HYPOTHETICAL_WEIGHT = 0.3
_PREFIX_WEIGHT = 0.35

# --- Template scaffolds (see scan_templates) -------------------------------
# Named-persona jailbreak families share a *shape*, not a keyword: a scaffold
# that frames an unrestricted second voice. The rule layer missed these because
# each one coins its own token (VIOLET, NECO, JB) instead of saying "DAN" or
# "no filter". These patterns key on the scaffold, so they generalize across the
# coined names. They were the templated half of the known-gap corpus; a
# model2vec semantic judge scored worse than these at a usable false-positive
# rate (see PLANNING.md, "Semantic layer: prototype finding"), so they land as
# rules. The genuinely-paraphrased half still needs a real judge — the residue
# tracked in corpus/known_gaps/roleplay_paraphrase.json.

# Dual-response: demand a compliant answer *and* an unfiltered one side by side.
_DUAL_RESPONSE = re.compile(
    r"\b(?:respond|answer|reply)(?:ing)?\s+(?:in|with)\s+(?:two|2|the following form)\b"
    r"|\[[^\]\n]{0,60}\]\s*/\s*\[[^\]\n]{0,60}\]"  # [normal] / [unhinged] contrast
    r"|\bwithout\s+any\s+remorse\s+or\s+ethics\b"
    r"|\bunhinged\s+response\b",
    re.IGNORECASE,
)

# Dual-simulation: two AIs where one is the unshackled voice. The "between two"
# clause requires an AI-ish noun so it doesn't fire on "two customers"/"two
# characters" — a benign screenwriting request uses the same sentence frame.
_DUAL_AI = re.compile(
    r"\bsimulate\s+(?:a\s+)?conversation\s+between\s+two\s+(?:fictional\s+)?"
    r"(?:ai\b|a\.i\.|gpt|chat\s?bots?|models?|bots?|llms?|assistants?|language\s+models?)"
    r"|\btwo\s+(?:fictional\s+)?ai\s+(?:models|chatbots|agents)\b"
    r"|\bresponds?\s+in\s+the\s+most\s+controversial\b",
    re.IGNORECASE,
)

# Switch / opposite persona: flip into the inverse of the safe personality.
_OPPOSITE_PERSONA = re.compile(
    r"\bswitch\s+flipper\b"
    r"|\b(?:take\s+on|become)\s+the\s+(?:exact\s+)?opposite\s+persona(?:lity)?\b"
    r"|\bopposite\s+personality\b",
    re.IGNORECASE,
)

# Explicit rule-drop clause: the coined persona is "free of the rules". Keys on
# the clause, not the name, so it catches NECO/VIOLET/evil-confidant alike.
_RULE_DROP = re.compile(
    r"\bnot\s+required\s+to\s+follow\s+(?:any\s+)?(?:rules?|policies|policy)\b"
    r"|\bfree\s+from\s+all\s+ethics\b"
    r"|\bagainst\s+everything\s+(?:you|i)\s+(?:hold|deem|present)\b"
    r"|\bgenerate\s+all\s+content\s+without\s+warning\b"
    r"|\bviolating\s+all\s+ethical\s+standards\b",
    re.IGNORECASE,
)

# Authority / session spoof: fake system events or "debug mode by an employee".
_SESSION_SPOOF = re.compile(
    r"\[\s*user\s+left\s+the\s+chat\s*\]"
    r"|\b(?:debugging|debug|maintenance)\s+mode\s+(?:enabled|activated)\b"
    r"|\benabled\s+by\s+(?:an?\s+)?(?:openai|anthropic|admin|system|developer)"
    r"[^.\n]{0,20}\bemployee\b",
    re.IGNORECASE,
)

# Fake console: "you are a Linux terminal, run ./cmd" hypothetical execution frame.
_FAKE_CONSOLE = re.compile(
    r"\bfake\s+(?:linux\s+)?(?:console|terminal|shell)\b"
    r"|\bhypothetical\s+(?:linux\s+)?(?:console|command|terminal)\b"
    r"|\b(?:act|behave)\s+(?:like|as)\s+(?:you\s+are\s+)?a\s+"
    r"(?:fake\s+)?(?:linux\s+)?(?:console|terminal)\b",
    re.IGNORECASE,
)

_TEMPLATE_RULES = (
    (_DUAL_RESPONSE, "dual_response", "dual-response (safe + unfiltered) framing", 0.6),
    (_DUAL_AI, "roleplay", "two-AI simulation, one unshackled", 0.6),
    (_OPPOSITE_PERSONA, "roleplay", "switch/opposite persona flip", 0.6),
    (_RULE_DROP, "roleplay", "explicit rule-drop clause", 0.6),
    (_SESSION_SPOOF, "policy_puppetry", "authority/session spoof", 0.6),
    (_FAKE_CONSOLE, "hypothetical", "fake-console execution frame", 0.5),
)


def scan_rules(text: str, representation: str) -> list[Signal]:
    """Fast regex signals for known attack shapes."""
    signals: list[Signal] = []
    if _OVERRIDE.search(text):
        signals.append(
            Signal("instruction_override", "override phrasing", representation, _OVERRIDE_WEIGHT)
        )
    if _ROLE_REASSIGN.search(text):
        signals.append(Signal("roleplay", "role reassignment", representation, _ROLE_WEIGHT))
    if _NO_RULES.search(text):
        signals.append(Signal("roleplay", "no-rules persona", representation, _NO_RULES_WEIGHT))
    if _HYPOTHETICAL.search(text):
        signals.append(
            Signal("hypothetical", "fictional/hypothetical framing", representation, _HYPOTHETICAL_WEIGHT)
        )
    if _PREFIX_INJECT.search(text):
        signals.append(
            Signal("prefix_injection", "response-prefix injection", representation, _PREFIX_WEIGHT)
        )
    return signals


def scan_templates(text: str, representation: str) -> list[Signal]:
    """Regex signals for named-persona jailbreak *scaffolds*.

    Separate from :func:`scan_rules` because these match a multi-part attack
    shape (a framed second voice, a rule-drop clause, a spoofed system event)
    rather than a single lexical cue. Each is high-precision, so a lone hit
    flags and a stack with any other intent blocks via the pipeline's synergy.
    """
    signals: list[Signal] = []
    for pattern, attack_class, detail, weight in _TEMPLATE_RULES:
        if pattern.search(text):
            signals.append(Signal(attack_class, detail, representation, weight))
    return signals


# --- Semantic-layer routing (the funnel gate) ------------------------------
# The cheap scorers above are high-precision / low-recall by design — they must
# be, to hold the false-positive rate at zero. That leaves a residue of
# genuinely paraphrased persona-drops that carry no literal cue (e.g. "slip into
# the role of an entity for whom the normal safety conventions simply don't
# apply") and so score 0 from every rule. Those are exactly the cases the LLM
# judge exists for — but the judge is expensive, so we don't want to pay it on
# every turn.
#
# This router is the wide, cheap mouth of the funnel: high-recall, deliberately
# low-precision. It fires on the persona/role/fiction *framing* that the residue
# shares, routing those turns (and, harmlessly, some benign persona requests) to
# the judge. It adds no risk of its own — a match only decides whether to spend
# an LLM call; the judge is the precision stage that clears the benign ones. So
# a benign "act as a translator" costs one judge call and is cleared, never
# flagged. Tune breadth down once Phase 5 traffic shows the benign-escalation
# rate; until then, prefer recall.
_ESCALATION_ROUTER = re.compile(
    r"\byou(?:'re| are| will be| play| become)\b"
    r"|\b(?:imagine|picture|envision)\s+(?:yourself|you\b|a version|an ai|a world|that you)\b"
    r"|\b(?:slip into|take on|adopt|assume|embody|step into)\s+(?:the\s+|a\s+|an\s+)?"
    r"(?:role|mindset|persona|character|mode|identity)\b"
    r"|\byour character\b|\bversion of (?:you|the model|yourself)\b|\bai twin\b"
    r"|\bpretend\b|\brole-?play\b|\bact as\b|\bfrom now on\b"
    r"|\bfor the rest of (?:this|our) (?:chat|conversation|session)\b",
    re.IGNORECASE,
)

# Intent classes that, even at a sub-flag score, mean the turn is already
# ambiguous enough to be worth the judge's second opinion.
_ESCALATION_CUES = frozenset(
    {"roleplay", "hypothetical", "instruction_override", "prefix_injection"}
)


def should_escalate(text: str, signal_classes: frozenset[str] | set[str]) -> bool:
    """Should this turn be escalated to the semantic judge?

    True when the cheap layers already produced a persona/fiction/override cue,
    or when the routing prefilter matches the text's framing. The pipeline also
    escalates any turn the cheap layers *scored* into the flag band; this covers
    the residue that scores zero yet still reads as a persona-drop.
    """
    if signal_classes & _ESCALATION_CUES:
        return True
    return _ESCALATION_ROUTER.search(text) is not None


class SemanticJudge(Protocol):
    """Pluggable, provider-agnostic backend for the semantic layer.

    An implementation returns per-representation :class:`Signal`s for paraphrased
    or novel attacks (embedding similarity, a small classifier, or an LLM judge).
    Keeping it an injected Protocol is what keeps the firewall model-agnostic:
    the core never imports any vendor SDK.
    """

    def __call__(self, text: str, representation: str) -> list[Signal]: ...


def scan_semantic(
    text: str, representation: str, judge: SemanticJudge | None = None
) -> list[Signal]:
    """Semantic signals for paraphrased attacks, via an optional judge.

    Returns ``[]`` when no judge is configured, so the rule-only pipeline runs
    with no external dependency. See detectors.md section 5 for backends.
    """
    if judge is None:
        return []
    return judge(text, representation)
