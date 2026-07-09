# Integration guide

promptpaws is a Python library. The default pipeline needs no environment
variables, writes no files, makes no network calls, and has no runtime
dependencies. Logging and model-based judges are opt-in.

## Choose an integration

| Your application | Use |
|---|---|
| Python backend | Import `guard()` and `screen_output()` |
| Backend in another language | Deploy a small Python guard endpoint and call it over HTTPS |
| MCP-capable assistant or agent | Run `promptpaws-mcp` |
| Shell or CI check | Run `promptpaws check "some text"` |

MCP is useful when an assistant discovers and calls tools. For an application
backend, a library import or REST call is simpler.

## Python backend

Run the guardrail at the backend boundary, around your existing model call:

```python
from promptpaws import SessionTracker, guard, screen_output

tracker = SessionTracker()

def call_model(messages):
    ...  # your existing OpenAI, Anthropic, or other model call

def handle_turn(session_id: str, user_message: str) -> str:
    g = guard(
        "a customer-support assistant for Acme Co.",
        user_message,
        policy="no legal advice",
    )

    if g.blocked:
        return g.refusal  # do not call the model

    response = call_model(g.call.messages())
    screened = screen_output(response, canaries=g.call.canaries)

    session = tracker.record(
        session_id,
        firewall=g.verdict,
        screening=screened,
    )
    if session.action.value in {"refuse", "reset"}:
        return "Let's start fresh — I can't continue down this path."

    return screened.safe_response
```

Two details matter:

- Send `g.call.messages()` to the model, not the raw user message.
- Pass `g.call.canaries` to `screen_output()`.

`examples/backend_loop.py` is a runnable version with a fake model.

### Custom refusal text

Set it per call:

```python
g = guard(..., refusal="I can only help with billing questions.")
screened = screen_output(..., refusal="Reply has been redacted.")
```

Or set the process-wide default:

```bash
export PROMPTPAWS_REFUSAL="I can't help with that right now."
```

An explicit function argument takes precedence over the environment variable.

## Backend in another language

Run promptpaws in a small Python endpoint. The endpoint screens the input and
returns either a refusal or the hardened messages your existing backend should
send to its model:

```python
from promptpaws import guard

def check_message(message: str) -> dict:
    g = guard("a customer-support assistant", message)
    if g.blocked:
        return {"blocked": True, "refusal": g.refusal}

    return {
        "blocked": False,
        "messages": g.call.messages(),
        "canaries": list(g.call.canaries),
    }
```

Expose `check_message()` through your Python web framework. Here is a complete
stdlib handler suitable for a small Python function:

```python
import json
from http.server import BaseHTTPRequestHandler
from promptpaws import guard

class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        message = str(json.loads(self.rfile.read(length) or b"{}")["message"])
        guarded = guard("a customer-support assistant", message)

        if guarded.blocked:
            body = {"blocked": True, "refusal": guarded.refusal}
        else:
            body = {
                "blocked": False,
                "messages": guarded.call.messages(),
                "canaries": list(guarded.call.canaries),
            }

        payload = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
```

Call it before the model from the existing backend:

```js
const guarded = await fetch(process.env.PROMPTPAWS_GUARD_URL, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ message: userMessage }),
}).then((response) => response.json());

if (guarded.blocked) {
  return { reply: guarded.refusal };
}

const response = await callModel(guarded.messages);
```

If promptpaws and the chat backend are separate services, protect the guard
endpoint with service authentication. Do not expose model or service keys to
the browser.

Output screening must run after the model call. Keep it in the Python service
if the non-Python backend cannot import promptpaws.

## MCP

Install the MCP extra:

```bash
pip install "promptpaws[mcp] @ git+https://github.com/juliewan/promptpaws.git"
```

The default transport is stdio:

```bash
claude mcp add promptpaws -- promptpaws-mcp
```

Equivalent MCP client configuration:

```json
{
  "mcpServers": {
    "promptpaws": {
      "command": "promptpaws-mcp"
    }
  }
}
```

The server exposes `check_input`, `harden_prompt`, `screen_output`, and
`session_risk`.

To host it as an HTTP service:

```bash
export PROMPTPAWS_TRANSPORT=streamable-http
export PROMPTPAWS_HOST=0.0.0.0
export PROMPTPAWS_PORT=8000
promptpaws-mcp
```

Put authentication and TLS in front of a hosted MCP server. Use a persistent
store for logs and session state if requests can reach more than one process.

## Optional logging

Decision records can contain raw user input. Treat the destination as sensitive
production data: restrict access and set a retention policy.

### Local JSONL

For library use:

```python
from promptpaws import JsonlSink, Monitor, inspect_input

monitor = Monitor(JsonlSink("logs/decisions.jsonl"))
verdict = monitor.firewall(
    inspect_input(user_message),
    raw_input=user_message,
)
```

For the MCP server:

```bash
export PROMPTPAWS_LOG=logs/decisions.jsonl
promptpaws-mcp
```

Inspect the file with ordinary JSONL tools:

```bash
tail -f logs/decisions.jsonl
jq 'select(.decision != "pass")' logs/decisions.jsonl
```

Do not use a local JSONL file on an ephemeral serverless filesystem. Send
records to platform logs or a hosted store instead.

### Supabase

Run `examples/supabase_decisions.sql` in the project, then configure the
server-side credentials:

```bash
export SUPABASE_URL=https://<project>.supabase.co
export SUPABASE_SERVICE_KEY=<service-role-key>
promptpaws-mcp
```

Never put the service-role key in browser code.

The MCP server chooses its sink in this order:

1. Supabase when its URL and service key are set.
2. Local JSONL when `PROMPTPAWS_LOG` is set.
3. No logging otherwise.

Library code can use the same selection:

```python
from promptpaws import Monitor, sink_from_env

monitor = Monitor(sink_from_env())
```

To review production findings locally:

```bash
promptpaws supabase pull-novel
```

This writes deduplicated candidates to
`corpus/inbox/supabase_novel.json`. Review and scrub them before moving them
into the attack corpus.

To apply retention:

```bash
promptpaws supabase purge --conversation-days 90 --session-hours 24
```

### Custom destination

A sink only needs an `emit()` method:

```python
class StdoutSink:
    def emit(self, record) -> None:
        print(record.to_json())

monitor = Monitor(StdoutSink())
```

Replace `print()` with a call to your logging or storage provider. Monitoring
failures should not take down the chat path.

## Optional model judges

There are two separate judges:

- `LLMJudge` examines ambiguous input for attacks that deterministic rules may
  miss.
- `LLMPolicyJudge` checks model output against your application policy.

Both accept a `complete(prompt) -> str` function, so they can use the same model
provider as the rest of your application. Construct judge objects at module
scope so a warm process can reuse their in-memory caches.

### Semantic input judge

The input judge is not called on every turn. Cheap checks run first and only
ambiguous input is escalated. A judge request adds model cost and latency to
those turns; without a judge, the deterministic pipeline is unchanged.

Example using OpenAI:

```python
from openai import OpenAI
from promptpaws import LLMJudge, guard

client = OpenAI()

def complete(prompt: str) -> str:
    response = client.responses.create(
        model="gpt-5-nano",
        input=prompt,
        max_output_tokens=50,
    )
    return response.output_text

judge = LLMJudge(complete, timeout=5.0)

def handle_input(message: str):
    return guard("a customer-support assistant", message, judge=judge)
```

For another provider, replace only `complete()`. It receives a prompt and must
return the model's response as a string.

### Built-in OpenAI adapter

The MCP server can create the semantic judge from environment variables:

```bash
export OPENAI_API_KEY=<server-side-key>
export PROMPTPAWS_JUDGE_MODEL=gpt-5-nano
promptpaws-mcp
```

Library code can use the same adapter:

```python
from promptpaws import guard, semantic_judge_from_env

judge = semantic_judge_from_env()
g = guard("a customer-support assistant", user_message, judge=judge)
```

`semantic_judge_from_env()` returns `None` when no API key is configured.

### Output policy judge

Use the policy judge when output must follow a domain-specific rule:

```python
from promptpaws import LLMPolicyJudge, screen_output

policy_judge = LLMPolicyJudge(
    complete,
    policy="Do not provide legal or medical advice.",
)

screened = screen_output(
    response,
    canaries=g.call.canaries,
    policy_judge=policy_judge,
)
```

For the MCP server, setting `PROMPTPAWS_POLICY` alongside the OpenAI key enables
the output policy judge:

```bash
export PROMPTPAWS_POLICY="Only answer questions about Acme's products."
```

Library code can construct it with `policy_judge_from_env()`.

### Serverless behavior

An in-memory judge cache belongs to one running instance. Vercel and similar
platforms may reuse a warm instance, but cold starts and scaled-out instances
begin with empty caches. That can repeat judge calls for the same ambiguous
input; it does not cause a judge call on every turn.

Use a shared cache if cross-instance deduplication matters.

## Deployment notes

- Firewall, hardening, and output screening are stateless.
- `SessionTracker` stores state in memory. Use a shared store when requests for
  one conversation can reach different processes.
- Local JSONL logs require persistent disk. On serverless platforms, use stdout
  or a hosted sink.
- Keep model, Supabase, and service credentials in server-side environment
  variables.
- The package is Python. Non-Python backends use a REST endpoint or hosted MCP
  server.

## Environment variables

All variables are optional.

| Variable | Effect | Default |
|---|---|---|
| `PROMPTPAWS_REFUSAL` | Default block response | `"I can't help with that."` |
| `PROMPTPAWS_LOG` | Append decision records to this JSONL file | no logging |
| `PROMPTPAWS_SUPABASE_URL` | Supabase URL; falls back to `SUPABASE_URL` | unset |
| `PROMPTPAWS_SUPABASE_SERVICE_KEY` | Supabase service key; falls back to `SUPABASE_SERVICE_KEY` | unset |
| `PROMPTPAWS_SUPABASE_TABLE` | Decision table | `promptpaws_decisions` |
| `PROMPTPAWS_OPENAI_API_KEY` | Built-in judge key; falls back to `OPENAI_API_KEY` | no judge |
| `PROMPTPAWS_JUDGE_MODEL` | Built-in judge model; falls back to `JUDGE_MODEL` | `gpt-5-nano` |
| `PROMPTPAWS_JUDGE_TIMEOUT` | Maximum wait for a judge result, in seconds | `5` |
| `PROMPTPAWS_JUDGE_HTTP_TIMEOUT` | HTTP timeout for the built-in adapter | `30` |
| `PROMPTPAWS_POLICY` | Output policy; enables the policy judge | no policy judge |
| `PROMPTPAWS_TRANSPORT` | MCP transport: `stdio`, `streamable-http`, or `sse` | `stdio` |
| `PROMPTPAWS_HOST` | Bind address for HTTP MCP transports | `127.0.0.1` |
| `PROMPTPAWS_PORT` | MCP port; falls back to `PORT` | `8000` |
