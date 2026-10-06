# Mnestiq Evidence Format: v0.2 (draft)

Status: **draft**. Breaking changes are possible until v1.0. The machine-readable
definition is [`schema/record.schema.json`](schema/record.schema.json); where this
document and the schema disagree, the schema wins for structure and this document
wins for hashing and verification rules.

The key words MUST, SHOULD and MAY are used as in RFC 2119.

## 1. Purpose

Observability traces answer *"what did my agent do?"*. Evidence answers
*"which agent, run and step caused this action, what input drove it, who
authorized it: and can we prove the record hasn't been altered?"*

The format is designed for three things that ordinary traces don't provide:

1. **Attribution**: every event carries the identity of the run, step, agent,
   operator and sandbox, so actions seen in infrastructure logs can be tied back
   to the agent step that caused them.
2. **Provenance**: every piece of model context is tagged with where it came
   from (`user`, `web`, `tool_output`, ...), at capture time. This is what makes
   prompt-injection analysis (taint tracking) possible after the fact.
3. **Tamper evidence**: records are hash-chained and periodically signed, so
   modification, deletion, insertion and reordering are detectable.

## 2. Threat model

Protects against: an insider or attacker with write access to stored evidence who
edits, deletes, reorders or forges records *after* they were written, provided the
verifier pins the recorder's public key (section 6.4).

Does **not** protect against:

- A compromised recorder host lying *at write time*. Evidence is tamper-evident,
  not truthful at source. Mitigate by correlating with independent infrastructure logs.
- Truncation: cutting the file back to any earlier checkpoint, or dropping records
  after the last one (section 6.5). Mitigate by keeping the latest checkpoint in a
  second place and verifying against it (section 6.6), or with an append-only sink
  (e.g. S3 Object Lock).
- Theft of the signing key. Keep it out of reach of the agent process: in a key store
  such as Azure Key Vault, or in a signing service under another account (section 6.7).
  Then someone who takes over the agent can obtain signatures only while in control,
  and cannot take the key away to re-sign history later.

## 3. Encoding

An evidence file is **JSON Lines**: UTF-8, one record per line, each line a JSON
object. Producers SHOULD write each line in canonical form (section 5.1). A file holds
exactly one chain.

Integers MUST be within +/-(2^53-1). Values that may exceed this (nanosecond
timestamps, 64-bit ids) MUST be encoded as strings. Floating-point NaN and
Infinity MUST NOT appear.

Unknown top-level fields MUST be prefixed `x-`; verifiers MUST ignore them
semantically (they are still covered by the record hash).

## 4. Records

Every record has these chain fields:

| Field | Type | Meaning |
|---|---|---|
| `spec_version` | `"0.2"` | Format version (section 9). |
| `kind` | `"event"` \| `"checkpoint"` | Record type. |
| `chain_id` | string | Identifies the chain. Constant within a file. |
| `seq` | integer | 0-based position in the chain. Contiguous. |
| `ts` | object | `wall`: RFC 3339 UTC with 6 fractional digits. `mono_us`: monotonic clock, microseconds. |
| `prev_hash` | hash | `record_hash` of record `seq-1`; for `seq` 0, `sha256:` followed by 64 zeros. |
| `record_hash` | hash | See section 5.2. |

A *hash* is the string `sha256:` followed by 64 lowercase hex digits.

### 4.1 Events

| Field | Required | Meaning |
|---|---|---|
| `event_type` | yes | `run_start`, `run_end`, `llm_call`, `tool_call`, `approval`, `egress`, `note`, `heartbeat` (section 6.8). |
| `run_id` | yes | The run this event belongs to. |
| `parent_run_id` | | The run that spawned this one (sub-agents, handoffs). |
| `step_id` | | Position of the event within its run, from 0. |
| `agent_id` | yes | Which agent (logical identity, e.g. `support-bot`). |
| `operator_id` | | Human or service on whose behalf the agent acts. |
| `sandbox_id` | | Container / VM / sandbox the agent runs in. Joins to infrastructure logs. |
| `model` | | `provider`, `name` (requested), `version` (as reported by the provider), `params` (sampling). |
| `system_prompt_hash` | | Digest of the system prompt, for quick comparison across runs. |
| `context[]` | | Model input segments, each with `source` (section 7), optional `role` / `name`, and redactable `content`. |
| `output` | | Model output: redactable `content`, `stop_reason`, `response_id`. |
| `tool_calls[]` | | In `llm_call`: calls the model requested. In `tool_call`: the executed call, with `result`, `result_source`, `error`, `latency_ms`. |
| `approvals[]` | | `action`, `decision` (`approved`/`denied`), `approver`, `approver_type` (`human`/`policy`/`agent`), `reason`. |
| `effective_permissions` | | Snapshot of what the agent was allowed to do. Recorded on `run_start`. |
| `egress[]` | | Outbound requests and connections (section 4.3). |
| `usage`, `latency_ms`, `status`, `error`, `attributes` | | As named. |

### 4.2 Checkpoints

A checkpoint signs every record after the previous checkpoint (or from `seq` 0)
up to the record immediately before it.

| Field | Meaning |
|---|---|
| `covers` | `{from_seq, to_seq}`, inclusive. `to_seq` = this `seq - 1`. Non-empty. |
| `merkle_root` | Section 6.2, over the `record_hash` of each covered record in order. |
| `sig_alg` | `"ed25519"`, or `"ecdsa-p256-sha256"` (ECDSA over P-256 with SHA-256, for key stores without Ed25519). |
| `public_key` | Base64 of the raw public key: 32 bytes for Ed25519, the 65-byte uncompressed SEC1 point (`0x04` \|\| X \|\| Y) for P-256. |
| `key_id` | `ed25519:` or `p256:`, then the first 16 hex digits of SHA-256(raw public key). |
| `signature` | Signature over the signing payload (section 6.3), base64. Ed25519: 64 bytes. P-256: the 64 bytes r \|\| s, big-endian, with s at most n/2 (section 6.3). |
| `next_key` | Optional. `{sig_alg, public_key, key_id}`: hands the chain over to this key (section 6.7). |
| `timestamp_token` | Optional RFC 3161 TimeStampToken (DER, base64) whose message imprint is SHA-256 of the signature bytes. |

### 4.3 Egress and identity propagation

Infrastructure logs (VPC flow logs, firewalls, proxies, cloud audit logs) see
connections but not agents. Egress events carry the keys to join them:

| Field | Meaning |
|---|---|
| `egress_id` | Unique per request / connection. |
| `protocol` | `http` (request seen at the HTTP client) or `tcp` (any other outbound TCP connection). |
| `method`, `url`, `host`, `status` | HTTP only. `url` MUST NOT contain userinfo or fragments; query values whose names look secret SHOULD be masked. |
| `source_ip`, `source_port` | Local end of the connection, before NAT. With `dest_*` and time, this matches a flow-log record. |
| `dest_ip`, `dest_port` | Remote end. |
| `public_ip` | NAT / gateway address, if the producer knows it. |
| `run_id_header` | Whether identity headers were sent. |
| `error` | Connection or request failure. |

When stamping is enabled, producers send these HTTP request headers:

| Header | Value |
|---|---|
| `X-Mnestiq-Run-Id` | The event's `run_id`. |
| `X-Mnestiq-Egress-Id` | The egress entry's `egress_id`. |

Proxy and gateway logs that capture these headers join to evidence by exact id
(high confidence). Flow logs join by the connection 4-tuple and time (lower
confidence: ports are reused). Producers SHOULD record the event's `sandbox_id` so
the join can be scoped to one container or host.

## 5. Hashing

### 5.1 Canonical JSON

All hashing uses the JSON Canonicalization Scheme, **RFC 8785** (JCS): object keys
sorted by UTF-16 code units, no whitespace, ECMAScript number serialization,
minimal string escaping, UTF-8 output.

### 5.2 Record hash

1. Copy the record and remove `record_hash`.
2. Remove the value of every redactable field (section 5.3), keeping its `*_hash`.
3. `record_hash = "sha256:" + hex(SHA-256(JCS(result)))`.

### 5.3 Redactable fields

| Location | Value field | Digest field |
|---|---|---|
| `context[i]` | `content` | `content_hash` |
| `output` | `content` | `content_hash` |
| `tool_calls[i]` | `arguments` | `arguments_hash` |
| `tool_calls[i]` | `result` | `result_hash` |

`*_hash = "sha256:" + hex(SHA-256(JCS(value)))`. Producers MUST write the digest,
and SHOULD write the value. A producer MAY omit a value it considers too large to
store; it then MUST list it in the top-level `x-omitted` array (e.g.
`"context[2].content (5242880 bytes)"`), so an omitted value is distinguishable
from one redacted later. Anyone holding the evidence MAY later delete the value
(leaving the digest); the chain still verifies. This allows sharing evidence with
a third party without disclosing prompts, customer data or tool output, while
still letting them check the value if it is disclosed separately.

## 6. Integrity

### 6.1 Chain

For every record: `seq` is the previous `seq + 1` (first is 0); `prev_hash` equals
the previous record's `record_hash`; `record_hash` recomputes per section 5.2; every
present redactable value matches its digest; `chain_id` is constant.

### 6.2 Merkle root

RFC 9162 section 2.1.1 Merkle Tree Hash with SHA-256. Leaf inputs are the raw 32-byte
digests of the covered `record_hash` values. Leaf = SHA-256(0x00 || leaf input);
node = SHA-256(0x01 || left || right); split at the largest power of two less than n.

### 6.3 Signing payload

`JCS(checkpoint minus {record_hash, signature, timestamp_token})`. The
`record_hash` of a checkpoint is then computed per section 5.2 and *does* cover the
signature and timestamp token.

For P-256, the signature is ECDSA with SHA-256 over the payload. An ECDSA signature
(r, s) is also valid as (r, n - s), so a third party could change a signature without
the key. Producers MUST write s in its low form (s <= n/2, where n is the order of the
P-256 group) and verifiers MUST reject any other, so every payload has one valid
signature per key.

### 6.4 Trust

A valid signature only proves the file is internally consistent. Someone who
rewrites the whole file can re-sign it with their own key. Verifiers MUST let
the user pin trusted public keys and MUST report checkpoints signed by any other
key as errors when keys are pinned. Without pinned keys, verifiers MUST warn.

A key that a trusted key handed the chain to (section 6.7) is trusted for the rest of
that chain. A hand-over signed by an untrusted key extends nothing.

### 6.5 Known limits

Records after the last checkpoint are covered only by the hash chain. Verifiers
MUST report how many trailing records are unsigned. Removal of complete trailing
checkpoint groups cannot be detected from the file alone: a file cut back to any
earlier checkpoint verifies. Keeping the latest checkpoint elsewhere (section 6.6),
a transparency log, or a separate WORM store closes this gap.

### 6.6 Head

A *head* is a copy of the most recent checkpoint record, stored apart from the
evidence file (another disk, host or account) and replaced as each checkpoint is
written. Given a head, a verifier MUST report an error unless the chain contains a
checkpoint with the head's `seq` and an identical `record_hash`, and the head's
`chain_id` matches. A chain that ends before the head's `seq` MUST be reported as
truncated. A head proves the file is at least as long as when the head was last
written; checkpoints written after that are covered by section 6.5 alone.

### 6.7 Signing keys and hand-overs

The signing key SHOULD be out of the agent's reach: in a hardware-backed key store
(the producer sends only SHA-256 of the payload), or in a separate signing service
running under another account. Such a service SHOULD sign only checkpoints for its own
key, only with a `ts.wall` close to its own clock, and per chain only the checkpoint
that starts right after the last one it signed, and SHOULD log every signature. Then
someone who controls the agent cannot have earlier checkpoints signed again.

A chain is signed by one key at a time. To change keys, the producer writes a
checkpoint signed by the current key with `next_key` naming the new one. Every later
checkpoint MUST be signed by the key named in the most recent `next_key`, or, if
there is none, by the key that signed the chain's first checkpoint. In a v0.2 record,
a checkpoint signed by any other key MUST be reported as an error, with or without
pinned keys. In a v0.1 record it MUST be reported as a warning.

Verifiers MUST check that `next_key.key_id` matches `next_key.public_key`.

### 6.8 Heartbeats

An agent that does nothing writes nothing, and so does a recorder that was stopped. To
tell the two apart, a producer MAY write a `heartbeat` event whenever nothing has been
signed for a set interval, followed by a checkpoint. Its `attributes.interval_s` gives
the interval in seconds.

Once a chain has a heartbeat with `interval_s`, verifiers MUST warn about any two
consecutive records whose `ts.wall` values are more than `2 * interval_s + 60` seconds
apart: the recorder was not running in between. This is a warning, not an error: the
evidence is intact, but there is a period it says nothing about. The same checkpoints,
sent to a second place as they are written, let that place raise the alarm while the
silence is happening rather than afterwards.

## 7. Provenance sources

| Source | Trusted? | Meaning |
|---|---|---|
| `system` | yes | System / developer prompt set by the deployer. |
| `user` | yes* | The human or calling application the agent serves. |
| `internal` | yes* | Output of the deployer's own system of record (account, contacts, configuration) that outsiders cannot write to. |
| `model` | n/a | The model's own earlier output. |
| `tool_output` | no | Output of a tool, origin otherwise unspecified. |
| `retrieved_doc` | no | Retrieval (RAG, file search, database rows). |
| `web` | no | Content fetched from the internet. |
| `agent_msg` | no | A message from another agent. |
| `memory` | no | Agent long-term memory (can carry earlier injections forward). |
| `unknown` | no | Origin could not be determined. |

\* "Trusted" means *authorized to instruct the agent*, not *correct*.

Producers MUST tag at capture time and SHOULD use the most specific source.
Tool output sources are typically configured per tool. Tag a tool `internal` only if
no outside party can put text into what it returns: an inbox, a shared calendar or a
ticket queue is not internal, even when it is the deployer's own system.

## 8. Relationship to OpenTelemetry

This format complements, not replaces, the OpenTelemetry GenAI semantic
conventions. Field correspondence (informative; check the current semconv
version):

| Evidence field | OTel GenAI attribute |
|---|---|
| `model.provider` | `gen_ai.provider.name` |
| `model.name` | `gen_ai.request.model` |
| `model.version` | `gen_ai.response.model` |
| `output.response_id` | `gen_ai.response.id` |
| `output.stop_reason` | `gen_ai.response.finish_reasons` |
| `usage.input_tokens` / `output_tokens` | `gen_ai.usage.input_tokens` / `gen_ai.usage.output_tokens` |
| `tool_calls[].name` / `id` | `gen_ai.tool.name` / `gen_ai.tool.call.id` |
| `agent_id` | `gen_ai.agent.id` |

What OTel does not yet cover, and this format adds: per-segment provenance,
run/operator/sandbox attribution for egress correlation, approvals, effective
permissions, redactable digests, and the hash chain with signed checkpoints.

## 9. Versioning

`spec_version` changes on any change to hashing, required fields or semantics.
Verifiers MUST reject versions they don't implement.

v0.2 adds P-256 signatures, key hand-overs (`next_key`) and `heartbeat` events. Hashing and every v0.1
field are unchanged, so a v0.2 verifier verifies v0.1 files as they are. A chain MAY
move from v0.1 to v0.2 part-way (a recorder upgraded on a running chain), and MUST NOT
move back. A v0.1 record MUST NOT use P-256, `next_key` or `heartbeat`.
