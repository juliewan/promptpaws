"""Docs drift guard: execute the runnable examples in README.md and INTEGRATION.md.

Guards against exactly the kind of silent drift that already happened once
(the repo-layout list omitted judge.py until the 2026-07-06 reorg): if a
documented code block stops matching the real API, this test fails loudly
instead of a reader hitting a NameError/ImportError on copy-paste.

Not every python block is executed. Skipped, each for its own reason:
the Anthropic/OpenAI/Ollama judge snippets (need a real vendor SDK plus an
API key or a local server); the `g = guard(purpose, user_message,
judge=judge)` continuation and the Monitor logging snippet's second line
(both use names bound only in surrounding prose, not standalone).
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
INTEGRATION = ROOT / "INTEGRATION.md"
SRC = ROOT / "src" / "promptpaws"
_PY_FENCE = re.compile(r"```python\n(.*?)```", re.S)
_ENV_VAR = re.compile(r"PROMPTPAWS_[A-Z_]+")


def _python_block_containing(doc: Path, marker: str) -> str:
    hits = [b for b in _PY_FENCE.findall(doc.read_text()) if marker in b]
    assert hits, (
        f"{doc.name} no longer has a python code block containing {marker!r} -- "
        "did this example move or get rewritten?"
    )
    return hits[0]


def test_backend_wiring_loop_defines_a_working_handle_turn():
    code = _python_block_containing(
        README, "from promptpaws import guard, screen_output, SessionTracker"
    )
    ns: dict = {"your_model": lambda messages: "a canned reply"}
    exec(compile(code, "README.md:backend-wiring", "exec"), ns)
    assert ns["handle_turn"]("readme-test-session", "what are your hours?") == "a canned reply"


def test_integration_handler_snippet_still_matches_the_api():
    # Only defines names -- do_POST is never invoked -- so this is a smoke test
    # that the imports and call shape (guard, screen_output, ModelCall) are
    # still current, not a live HTTP test.
    code = _python_block_containing(INTEGRATION, "from http.server import BaseHTTPRequestHandler")
    ns: dict = {}
    exec(compile(code, "INTEGRATION.md:handler", "exec"), ns)
    assert "handler" in ns


def test_integration_guide_documents_every_env_var():
    # INTEGRATION.md's reference table claims to be the complete configuration
    # surface; hold it to that. Any PROMPTPAWS_* var read anywhere in src/ must
    # appear in the guide.
    read_in_src = {
        var
        for path in SRC.rglob("*.py")
        for var in _ENV_VAR.findall(path.read_text())
    }
    documented = set(_ENV_VAR.findall(INTEGRATION.read_text()))
    missing = read_in_src - documented
    assert not missing, f"INTEGRATION.md omits env vars read in src/: {sorted(missing)}"
