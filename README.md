# Mnestiq

**A flight recorder for AI agents.** Tamper-evident, signed evidence of what an agent
saw, decided and did, built for incident response rather than dashboards.

When an agent emails the customer list to an attacker, observability traces tell you
*that* it happened. Evidence tells you *which* run and step did it, that the
instruction came from a web page rather than the user, that an auto-approve policy
waved it through, and lets you prove none of that was edited after the fact.

```
firewall: 10.0.4.17:53120 -> 198.51.100.9:25 (50 bytes)   [no agent identity]

mnestiq:  agent=support-bot run=c7831ff7 step=6 sandbox=container:7f3a9c operator=acme-helpdesk
          untrusted input earlier in the run: step 4: web via fetch_page
          authorized by policy:email-auto-approve (policy): recipient not checked against customer domain
```

## What it does

- **Attribution:** every event carries `run_id`, `step_id`, `parent_run_id`,
  `agent_id`, `operator_id` and `sandbox_id` (auto-detected for containers and k8s pods).
- **Egress identity:** outbound HTTP gets `X-Mnestiq-Run-Id` / `X-Mnestiq-Egress-Id`
  headers, and every outbound request *and* raw TCP connection (SMTP, databases, sockets)
  is recorded with its local and remote IP and port: the join key to flow and firewall logs.
- **Provenance:** every piece of model context is tagged at capture time:
  `system`, `user`, `model`, `tool_output`, `retrieved_doc`, `web`, `agent_msg`,
  `memory`. That's what makes prompt-injection analysis possible afterwards.
- **Tamper evidence:** records are hash-chained (RFC 8785 canonical JSON, SHA-256)
  and periodically sealed by Ed25519-signed Merkle checkpoints (RFC 9162 trees).
  Edits, deletions, insertions and reordering fail verification.
- **Redaction that keeps the proof:** strip prompts, tool arguments and tool output
  before handing evidence to an auditor; the chain still verifies.
- **Drop-in SDK capture:** wraps the Anthropic and OpenAI clients (sync and async,
  Chat Completions and Responses APIs). Recording fails open: it never breaks the agent.

## Quick start

```bash
pip install "mnestiq[anthropic]"     # or mnestiq[openai]
mnestiq keygen --out keys
```

```python
import anthropic
from mnestiq import FileSink, Recorder
from mnestiq.keys import load_private_key
from mnestiq.egress import instrument_egress
from mnestiq.integrations.anthropic import instrument_anthropic

recorder = Recorder(FileSink("evidence.jsonl"), agent_id="support-bot",
                    operator_id="acme-helpdesk", signing_key=load_private_key("keys/signing.key"))

@recorder.tool(source="web")          # output of this tool is untrusted web content
def fetch_page(url: str) -> str: ...

client = instrument_anthropic(anthropic.Anthropic(), recorder)
instrument_egress()                   # stamp + record outbound connections during runs

with recorder.run(effective_permissions={"email": "send"}):
    client.messages.create(model="claude-sonnet-5-5", max_tokens=1024, messages=[...])

recorder.close()                      # writes the final signed checkpoint
```

```bash
mnestiq verify evidence.jsonl --trusted-key keys/signing.pub
mnestiq inspect evidence.jsonl
mnestiq redact evidence.jsonl evidence.redacted.jsonl
```

### Dashboard

```bash
mnestiq dashboard evidence/ --trusted-key keys/signing.pub
```

A local investigation view at `http://127.0.0.1:8765`: runs and sub-runs, a step-by-step
timeline with every piece of model context colored by provenance, findings (below), the
verification status of every record (sealed, unsealed, or tampered), and a connection
finder: paste an `ip:port` from a firewall or flow log and jump to the agent step that
opened it. It live-updates while agents write.

| Rule | Name | Fires when |
|---|---|---|
| `MNQ-001` | untrusted argument | A tool call's arguments carry an email address, URL, account number or long number that appears in untrusted content and nowhere in the system prompt or the user's messages. |
| `MNQ-002` | auto-approval | An action was approved without a human after untrusted content reached the model. |
| `MNQ-003` | egress after taint | An outbound connection (not to loopback) followed untrusted content reaching the model. |
| `MNQ-004` | untrusted sensitive action | A sensitive action (credentials, permissions, deletion, payments, bookings) ran with an argument value that appears in untrusted content and not in the user's or system's words. Mark tools with `@recorder.tool(sensitive=True)`; unmarked tools are judged by name. |

`MNQ-001` is the signature of a hijack: an injected instruction has to put the attacker's
address, account or URL into a tool call. `MNQ-004` covers hijacks with no destination, such as
"change the password to ..." or "delete file 13". Findings describe what was observed, not a
verdict: an agent that visits a link a colleague posted triggers `MNQ-001` too. The same
rules are available in Python as `mnestiq.findings`.

It stays on your machine: it binds to loopback only, rejects non-local `Host` headers,
renders evidence strictly as text, and its Content-Security-Policy forbids the page from
loading or contacting anything but the local server.

To see it with live data (no API keys needed):

```bash
python examples/live_agent.py --out evidence           # keeps a scripted agent running
mnestiq dashboard evidence --trusted-key evidence/live.pub
```

See [`examples/injection_incident.py`](examples/injection_incident.py) for a full
incident: an injected web page leads to exfiltration over a raw TCP connection; a
firewall log entry is traced back to the exact agent step; a tampered approval is
caught; a redacted copy is shared.

## Running in production

The recorder runs inside your agent, so it is built to never be the thing that breaks it.

| Concern | Behaviour |
|---|---|
| **Recording fails** (disk full, closed sink, odd values) | The agent carries on. Failures are counted in `recorder.failures`, logged on the `mnestiq` logger, and warned about once. Pass `strict=True` to raise instead, if an unrecorded action is worse than a failed one. |
| **Process dies mid-write** | On restart, `FileSink` moves the torn last line to `<file>.torn-<time>` (never deleted), the chain resumes from the last complete record, and a `note` event records the recovery. A write that fails part-way is truncated, so the file never holds half a record. |
| **Huge prompts or tool output** | Values over `max_content_bytes` (default 1 MiB) are stored as their hash only and listed in `x-omitted`; the chain still verifies. |
| **Worker threads** | Threads don't inherit the active run. Wrap work with `run.bind(fn)`, e.g. `pool.submit(run.bind(fetch), url)`. |
| **Timestamp authority down** | The checkpoint is still signed and written; only the RFC 3161 token is skipped, with a warning. |
| **Power loss** | `FileSink(path, fsync=True)` forces each record to disk before the agent continues. |
| **Someone deletes the end of the file** | `Recorder(..., on_checkpoint=HeadFile("/other/disk/agent.head.json"))` keeps the latest checkpoint in a second place; `mnestiq verify evidence.jsonl --head /other/disk/agent.head.json` then reports a file cut back to an earlier checkpoint. |
| **Sensitive content** | New evidence files are created owner-read/write only. Use `mnestiq redact` before sharing. |
| **Large evidence in the dashboard** | The dashboard verifies the whole file but shows the most recent 20,000 records. |

## Repository layout

| Path | What |
|---|---|
| [`spec/SPEC.md`](spec/SPEC.md) | The evidence format, hashing and verification rules. |
| [`spec/schema/`](spec/schema/) | JSON Schema (2020-12) for records. |
| [`python/`](python/) | Recorder, verifier and CLI. |
| [`examples/`](examples/) | Runnable demos. |

## Security model in one paragraph

The format makes evidence **tamper-evident after it is written**. It does not make
a compromised host tell the truth at write time. On its own, a file can be cut back
to any earlier checkpoint without detection; keep the latest checkpoint somewhere
else with `HeadFile` and verify with `--head` to close that. Keep the signing key
outside the agent's sandbox. A signature only means something if you **pin the
recorder's public key** with `--trusted-key`; otherwise someone who rewrites the whole
file can re-sign it. See [SPEC.md, sections 2 and 6](spec/SPEC.md).

## Status and roadmap

v0.1 draft. Done: spec, verifier, Python recorder, Anthropic + OpenAI capture,
egress identity propagation (httpx, requests, raw TCP), local dashboard.

Next:
1. Out-of-process signing daemon; RFC 3161 timestamping and external anchoring;
   S3 Object Lock sink.
2. Automatic run propagation into executors (today: `run.bind`); aiohttp; subprocess egress.
3. OpenAI Agents SDK and LangGraph capture; streaming output capture.
4. TypeScript SDK; MCP proxy.
5. Spec test vectors; Merkle inclusion proofs for selective disclosure.

## Development

```bash
cd python
python -m venv .venv && source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -e ".[dev,anthropic,openai]" httpx requests ruff mypy
pytest
ruff check src tests
mypy src
```

The test suite never touches the network beyond this machine: `tests/_netguard.py`
blocks any connection or DNS lookup that isn't loopback, so a test that tried would
fail rather than quietly reach the internet.

## Security

Please report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
