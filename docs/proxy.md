# Recording without code changes: the model API proxy

The recorder runs inside a Python agent. For everything else (agents in other languages,
frameworks you can't change, tools that only let you set a base URL), `mnestiq proxy` records
the agent's model calls from outside it. The agent talks to the proxy instead of the provider.
The proxy passes each request on unchanged with the agent's own API key, returns the answer
unchanged as it streams in, and writes each model call to a signed evidence file. That file is
the same format the recorder writes, so `mnestiq verify`, the dashboard, the findings and the
Workbench work on it as they are.

## Start it

```bash
mnestiq proxy evidence/support-bot.jsonl --agent support-bot --signer \
  --head /other/disk/support-bot.head.json
```

`--signer` signs with the signing service (`MNESTIQ_SIGNER`, `MNESTIQ_SIGNER_TOKEN`, see
[signing.md](signing.md)). `--azure-key URL` signs with Azure Key Vault, and `--key PATH` with a
key file, for trying it out. After 5 quiet minutes it signs a heartbeat and anything not yet
signed (`--heartbeat-minutes`), and it signs everything before it stops on Ctrl+C or a service
stop (SIGTERM, or Ctrl+Break on Windows). A proxy killed outright leaves the records since its
last checkpoint unsigned. The proxy prints the address to use for each provider:

```text
recording support-bot's model calls to evidence/support-bot.jsonl
  openai     http://127.0.0.1:8787/openai/v1  ->  https://api.openai.com
  anthropic  http://127.0.0.1:8787/anthropic  ->  https://api.anthropic.com
```

## Point the agent at it

| Client | Setting |
|---|---|
| OpenAI SDKs (Python, Node, .NET, Go, Java) | `OPENAI_BASE_URL=http://127.0.0.1:8787/openai/v1`, or the client's base URL option |
| Anthropic SDKs | `ANTHROPIC_BASE_URL=http://127.0.0.1:8787/anthropic`, or the client's base URL option |
| Azure OpenAI | start with `--upstream azure=https://<resource>.openai.azure.com`, then use `http://127.0.0.1:8787/azure` as the endpoint |
| A local or self-hosted model server (Ollama, vLLM, LiteLLM) | start with `--upstream local=http://127.0.0.1:11434`, then use `http://127.0.0.1:8787/local/v1` |
| Frameworks (LangChain, LlamaIndex, Semantic Kernel, Microsoft Agent Framework, ...) | they call one of the SDKs above: set the base URL or endpoint on the model client they use |

Each upstream is reached at `/<name>/` on the proxy. `--upstream NAME=URL` adds one (repeatable).
The proxy reads requests in OpenAI's format unless the name or host says anthropic. Use
`NAME=anthropic:URL` or `NAME=openai:URL` to say which. Plain `http` upstreams are allowed only to
this machine.

## Runs

The proxy works out which run each call belongs to. Every record says which rule it used
(`attributes.grouping`), so an investigator knows how sure the grouping is:

1. `header`: the agent names its run in an `X-Mnestiq-Run` header. One line of client
   configuration, for example `OpenAI(default_headers={"X-Mnestiq-Run": ticket_id})`. The
   header is not passed on to the provider.
2. `traceparent`: an agent that uses OpenTelemetry already sends one. The run is the trace.
3. `previous_response`: a Responses API call that continues an earlier answer.
4. `tool_result`: the call hands back a tool result. Tool call ids belong to one answer.
5. `conversation`: the call holds an earlier call's whole conversation and more.
6. `new`: none of the above. A call that only repeats an earlier one word for word is a new
   run, because scheduled agents often start every run with the same words.

## Where tool results come from

Tool results the agent hands back to the model are untrusted (`tool_output`) unless you say
otherwise, per tool:

```bash
mnestiq proxy ... --tool-source fetch_page=web --tool-source crm_lookup=internal
```

## What it records, and what it cannot

It sees what the model was told (system prompt, the user's words, the tool results the agent
handed back) and what the model asked for (tool calls, answers, token use), with the time,
latency, the provider's request id and the connection's addresses. Streamed answers are recorded
whole.

It does not see:

- **whether a tool really ran**, or what it did. It sees the model ask for it, and on the next
  call, the result the agent says it got.
- **anything else the agent connected to.** Pair it with flow, proxy and firewall logs, or with
  the recorder's egress capture where you can add code.
- **AWS Bedrock** (its requests are signed for Bedrock's own address), **WebSocket APIs** such as
  realtime voice, and the results of **batch** jobs. Requests it does not read as model calls (the
  model list, files, token counting) are passed on and noted with their method and path.

## Findings

MNQ-001 (untrusted argument) and MNQ-005 (untrusted link in the answer) work on proxy evidence as
on the recorder's. MNQ-004 (untrusted sensitive action) looks at the tool calls the model asked
for, and says "requested". MNQ-006 (internal data to a new recipient) does the same, when the
proxy's tool sources label some tools `internal`. MNQ-002 and MNQ-003 need approvals and egress,
which the proxy does not see.

## Deploying it safely

- **Run it under its own account**, with the evidence in a folder only that account can write,
  and the signing key in the signing service or Key Vault, not in the agent's reach.
- **Let only the proxy reach the providers.** A firewall or egress rule that allows
  `api.openai.com`, `api.anthropic.com` and the rest only from the proxy stops an agent from
  going around it. Without that rule, a hijacked agent holding the key could call the provider
  directly, and only network logs would show it.
- **It listens on this machine only** unless you pass `--allow-network` and at least one
  `--allow-client` address range. Between the agent and the proxy the traffic is plain HTTP and
  carries the API key: keep it on the same host, or on a network you trust, or put TLS in front.
- **The API key passes through and is never written down.** Only an allowlist of request
  headers is recorded (the client and API version), and any key a provider echoes in an error is
  masked. Keys in a query string are masked in the evidence and the logs.
- **Recording never stops a call.** If writing evidence fails, the call goes through, and the
  failure is counted and logged.
- **Limits:** request bodies up to 64 MiB, answers kept up to 64 MiB, 256 connections at once.
  The proxy forwards only to the upstreams it was started with.

## Overhead

About 1.3 ms per call (2 ms at the 95th percentile), and about 0.9 ms more before the first
streamed chunk, measured against a provider on the same machine. Model calls take from half a
second to minutes.
