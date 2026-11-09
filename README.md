# Mnestiq

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.23800724.svg)](https://doi.org/10.5281/zenodo.23800724)

**A flight recorder for AI agents.** It records what an agent read, decided and did, where each piece
of its input came from, and signs the record, so a later change shows when you verify it with its key. When an agent
does something it shouldn't, you can show exactly which run and step did it, which untrusted input came
before it, and who or what approved it.

```bash
pip install mnestiq
mnestiq demo
```

The demo records a scripted support agent that reads a poisoned web page and emails customer data
out, then investigates it: the firewall connection traced to the agent step, a tampered copy caught,
a redacted copy for an auditor that still verifies. It ends in the dashboard. No API key, and
everything stays on your machine. Step by step for Windows, macOS and Linux:
[docs/install.md](docs/install.md).

```
firewall: 10.0.4.17:53120 -> 198.51.100.9:25 (50 bytes)   [no agent identity]

mnestiq:  agent=support-bot run=c7831ff7 step=6 sandbox=container:7f3a9c operator=acme-helpdesk
          untrusted input earlier in the run: step 4: web via fetch_page
          authorized by policy:email-auto-approve (policy): recipient not checked against customer domain
```

![Mnestiq dashboard showing a prompt-injection incident step by step](docs/dashboard.png)

## Record your own agent

Pick the way that fits. Each one writes the same signed evidence.

**1. No code changes: the proxy.** It sits between your agent and the model API. It works in any
language, for an agent that lets you set the base URL of an OpenAI or Anthropic format API.

```bash
pip install mnestiq
mnestiq keygen --out keys
mnestiq proxy evidence.jsonl --agent my-agent --key keys/signing.key
```

Then point the agent at it, in the agent's own terminal:

```bash
export ANTHROPIC_BASE_URL=http://127.0.0.1:8787/anthropic      # Anthropic SDKs
export OPENAI_BASE_URL=http://127.0.0.1:8787/openai/v1        # OpenAI SDKs
```

On Windows PowerShell: `$env:ANTHROPIC_BASE_URL = "http://127.0.0.1:8787/anthropic"`. Azure OpenAI,
and local models through Ollama, vLLM or LiteLLM, work too: see [docs/proxy.md](docs/proxy.md).

**2. From inside your Python code**, which also sees tool calls, approvals and network connections:

```python
import anthropic
from mnestiq import FileSink, Recorder
from mnestiq.keys import load_private_key
from mnestiq.integrations.anthropic import instrument_anthropic

recorder = Recorder(FileSink("evidence.jsonl"), agent_id="support-bot",
                    signing_key=load_private_key("keys/signing.key"))
client = instrument_anthropic(anthropic.Anthropic(), recorder)

with recorder.run():
    client.messages.create(model="claude-sonnet-5-5", max_tokens=200,
                           messages=[{"role": "user", "content": "Where is order 4711?"}])
recorder.close()                      # signs everything written so far
```

(`pip install "mnestiq[anthropic]"`, or `mnestiq[openai]` with `instrument_openai`.) The full example
below adds tools, their sources and network capture.

**Then look at what was recorded:**

```bash
mnestiq verify evidence.jsonl --trusted-key keys/signing.pub
mnestiq dashboard evidence.jsonl --trusted-key keys/signing.pub
```

## What it does

- **Attribution:** every step of a run carries `run_id`, `step_id` and `agent_id`, plus
  `parent_run_id`, `operator_id` and `sandbox_id` (auto-detected for containers and k8s pods) when
  it has them. Events the recorder writes for itself carry the ones they have.
- **Model calls:** wrap a client with `instrument_anthropic` or `instrument_openai`, or call
  `instrument_models(recorder)` to record calls to messages, chat completions and responses through
  those Python SDKs, including Azure OpenAI and clients created before the call. Calls through
  `client.post()` are recorded only with `instrument_models`. Streamed output is recorded when the
  stream ends. A stream cut short is marked as partly captured or not captured, and reported as
  `MNQ-000`. `post(cast_to=httpx.Response, stream=True)` is recorded without its output. Not seen:
  raw HTTP to a provider (put the API proxy in front of it), other SDKs, batch, embedding, image,
  audio and realtime calls, `responses.stream(response_id=...)`, a model call made inside another
  SDK call, a `client.request` method saved before instrumenting, and subprocesses.
- **Egress identity:** with `instrument_egress()`, outbound TCP connections (HTTP, SMTP, databases,
  sockets) made during a run through Python's socket layer and asyncio, including from threads
  started during the run and thread pool tasks submitted during it, are recorded with their local
  and remote IP and port. A recorded source address and port identify the connection. Traffic from a
  thread that carries on after its run ended is recorded and marked. httpx and requests get `X-Mnestiq-Run-Id` /
  `X-Mnestiq-Egress-Id` headers, and urllib and urllib3 get them for hosts in `stamp_hosts`. Python
  audit hooks add connections the patches missed, and datagrams, name lookups and process launches
  as notes. A TCP entry from an audit hook has no source IP or port, and may have no `dest_ip`.
  Through a proxy, `host` is the real destination and the IP and port are the proxy's.
  Not seen: native extensions with their own sockets, uvloop, the network traffic of child
  processes that are not Python, and the OpenAI and Anthropic API hosts when reached directly, left
  out by default because model calls are recorded on their own.
- **Provenance:** every piece of model context is tagged at capture time:
  `system`, `user`, `model`, `tool_output`, `retrieved_doc`, `web`, `agent_msg`,
  `memory`. That's what makes prompt-injection analysis possible afterwards.
- **Tamper evidence:** records are hash-chained (RFC 8785 canonical JSON, SHA-256)
  and periodically sealed by Ed25519-signed Merkle checkpoints (RFC 9162 trees).
  Edits, deletions, insertions and reordering of records under a signed checkpoint fail
  verification.
- **Redaction that keeps the proof:** strip prompts, tool arguments and tool output
  before handing evidence to an auditor; the chain still verifies.
- **Drop-in SDK capture:** wraps the Anthropic and OpenAI clients (sync and async,
  Chat Completions and Responses APIs). Once running, recording fails open: it does not break the
  agent. A `Recorder` pointed at a damaged file, or one it cannot read as evidence, refuses to start
  with `RecorderError`, by design.
- **No code changes needed:** `mnestiq proxy` records an agent's model calls from outside it,
  whatever language or framework it is written in, if it lets you set the base URL of an OpenAI or
  Anthropic format API. Point that base URL at the proxy.

## Recording in code, in full

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

A key file the agent can read is fine for trying it out. In production, keep the key where
the agent can't read it: `signer=SignerClient.from_env()` with `mnestiq signer serve` running
under another account, or `signer=AzureKeyVaultSigner(...)`. See [docs/signing.md](docs/signing.md).

## Dashboard and detection rules

```bash
mnestiq dashboard evidence/ --trusted-key keys/signing.pub
```

A local investigation view at the link it prints (`http://127.0.0.1:8765/?key=...`, whose key keeps
other accounts on the machine out): runs and sub-runs, a step-by-step
timeline with every piece of model context colored by provenance, findings (below), the
file's verification result, each record's status (sealed, unsealed, or tampered, worked out
in the page and not covered by the test suite), and a connection finder: paste an `ip:port` and jump
to the agent step with that recorded connection. It live-updates while agents write.

| Rule | Name | Fires when |
|---|---|---|
| `MNQ-001` | untrusted argument | A tool call's arguments carry an email address, URL, account number or long number that appears in untrusted content and nowhere in the system prompt or the user's messages. |
| `MNQ-002` | auto-approval | An action was approved without a human after untrusted content reached the model, and the approved call carries a value from that content. A policy approving a routine reply is not a lead. |
| `MNQ-003` | egress after taint | An outbound connection (not to loopback or the agent's own model API) after untrusted content reached the model, or a datagram or raw socket noted after it. Each destination is noted once before and once after untrusted content first reaches the model, up to 256 per kind each time. Past the limit after that point, the rules report `MNQ-000` rather than naming the destination. |
| `MNQ-004` | untrusted sensitive action | A sensitive action (credentials, permissions, deletion, cancellations, account changes, payments, bookings) ran with an argument value that appears in untrusted content and not in the user's or system's words. Mark tools with `@recorder.tool(sensitive=True)`. Unmarked tools are judged by name. |
| `MNQ-005` | untrusted link in answer | The model's answer carries an image, or a link with data in its query, to a host that appears in untrusted content and not in the user's or system's words. An image is fetched as soon as the answer is shown, so it can carry data out with no tool call. |
| `MNQ-006` | internal data to new recipient | A tool sent data from the company's own systems (tool output labelled `internal`) to an address or host that appears neither in those systems nor in the system prompt, such as the price list to a "new customer". No injection is needed. |

`MNQ-001` is the signature of a hijack: an injected instruction has to put the attacker's
address, account or URL into a tool call. `MNQ-004` covers hijacks with no destination, such as
"change the password to ...", "delete file 13" or "cancel order 4100". `MNQ-005` covers leaks
through the answer itself, such as an injected image link that carries the customer's email
address. `MNQ-006` covers data handed to someone who simply asked for it. Findings describe what was observed, not a
verdict: an agent that visits a link a colleague posted triggers `MNQ-001` too. A record the rules
cannot read (a field of a type the recorder never writes), a model call whose context could not be
restored in full, and a record the rules' work limit stopped all come back as `MNQ-000`, so a finding
that depended on them is never lost in silence. The same rules are available in Python as
`mnestiq.findings`.

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

The recorder runs inside your agent, so once it is running it is built to never be the thing that
breaks it. Starting is the exception, by design: a `Recorder` pointed at a damaged file, at one it
cannot read as evidence, or at one another recorder is writing refuses to start with `RecorderError`.

| Concern | Behaviour |
|---|---|
| **Recording fails** (disk full, closed sink, odd values) | The agent carries on. Failures are counted in `recorder.failures`, logged on the `mnestiq` logger, and warned about once. Pass `strict=True` to raise instead, if an unrecorded action is worse than a failed one. |
| **Process dies mid-write** | On restart, `FileSink` moves the torn last line to `<file>.torn-<time>` (never deleted), the chain resumes from the last complete record, and a `note` event records the recovery. A write that fails part-way is truncated. If truncating fails too, it is tried again before the next record, so no record is written onto half of another. |
| **Huge prompts or tool output** | Values over `max_content_bytes` (default 1 MiB) are stored as their hash only and listed in `x-omitted`, and the chain still verifies. Error text is cut to the same limit, and says so. |
| **Worker threads** | Without `instrument_egress()`, threads don't inherit the active run. Wrap work with `run.bind(fn)`, e.g. `pool.submit(run.bind(fetch), url)`. |
| **Signer down** (signing service or Key Vault) | Records are still written. The failure is counted and signing is tried again after `retry_after` seconds, covering everything since the last checkpoint. |
| **Recorder stopped or killed** | `Recorder(..., checkpoint_interval=300)` writes and signs a `heartbeat` when nothing was signed for 5 minutes. A recorder that stopped and started again then shows as a gap: `verify` warns about any silence longer than the heartbeats allow. One that never restarted leaves no gap in the file. The Evidence Vault can alert while it is happening. |
| **Timestamp authority down** | The checkpoint is still signed and written; only the RFC 3161 token is skipped, with a warning. |
| **Power loss** | `FileSink(path, fsync=True)` forces each record to disk before the agent continues. |
| **Someone deletes the end of the file** | `Recorder(..., on_checkpoint=HeadFile("/other/disk/agent.head.json"))` keeps the latest checkpoint in a second place; `mnestiq verify evidence.jsonl --head /other/disk/agent.head.json` then reports a file cut back to an earlier checkpoint. |
| **Sensitive content** | New evidence files are created owner-read/write only on Linux and macOS. On Windows a file takes its folder's access list, so keep evidence in a folder only the agent's account can read. Use `mnestiq redact` before sharing. It refuses a file it cannot redact safely: see [docs/install.md](docs/install.md#where-evidence-is-kept). |
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
out of the agent's reach, in a signing service or Azure Key Vault
([docs/signing.md](docs/signing.md)), so it can't be copied and used to re-sign history.
A signature only means something if you **pin the recorder's public key** with
`--trusted-key`; otherwise someone who rewrites the whole file can re-sign it. Keys change
only by a signed hand-over. See [SPEC.md, sections 2 and 6](spec/SPEC.md), and the
[threat model](docs/threat-model.md): every attack in its table is a test, and you can try your own
on the [break-it kit](examples/break-it/README.md).

## Status and roadmap

1.1. The evidence format ([SPEC.md](spec/SPEC.md), with [test vectors](spec/vectors) for other
implementations) and the documented Python API are stable: a change that would break existing evidence,
older verifiers or code using the documented API needs a 2.0. Done: verifier, Python
recorder, Anthropic and OpenAI capture, the model API proxy, egress identity (httpx, requests, raw
TCP), the local dashboard, signing outside the agent (signing service, Azure Key Vault) with signed key
hand-overs, heartbeats, RFC 3161 timestamps, salted redaction, and the agent's Entra Agent ID.

Support: best effort through GitHub issues, and security fixes for the latest release. Report
vulnerabilities privately ([SECURITY.md](SECURITY.md)).

Next:
1. A Claude Code plugin that records your coding agent.
2. Registering checkpoints with a SCITT transparency service ([docs/standards.md](docs/standards.md)), and
   an S3 Object Lock sink.
3. OpenAI Agents SDK and LangGraph capture, and an OpenTelemetry (GenAI) trace receiver.
4. Run identity stamped on aiohttp requests, and subprocess egress.
5. A TypeScript SDK and an MCP proxy.

## Development

```bash
cd python
python -m venv .venv && source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -e ".[dev,anthropic,openai,azure,timestamps]" httpx requests ruff mypy
pytest
ruff check src tests
mypy src
```

The test suite guards against reaching the network beyond this machine: `tests/_netguard.py`
blocks socket connections and `getaddrinfo` lookups that aren't loopback, so a test that tried
either would fail rather than quietly reach the internet. `gethostbyname` and `sendto` are not blocked.

## Security

Please report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## Citing

If you use the recorder or refer to it in your work, please cite it. The DOI
[10.5281/zenodo.23800724](https://doi.org/10.5281/zenodo.23800724) always points to the latest release, and "Cite this repository"
in the sidebar gives APA and BibTeX entries.

## License

Apache-2.0. See [LICENSE](LICENSE).
