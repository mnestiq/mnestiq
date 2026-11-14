# Mnestiq Evidence Format: v1.0

Status: **stable**. A change to hashing, required fields or the meaning of a field needs a new major
version (section 9). Additions that older verifiers can ignore safely come as minor versions. The machine-readable
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
  Then someone who takes over the agent cannot take the key away, and can obtain signatures
  only while in control. While in control, they can have records signed that are not signed
  yet, including records after the last checkpoint that they rewrote. Used directly, a key store
  signs a hand-over to their own key, as does a service with hand-overs enabled, and then this
  limit no longer holds.

## 3. Encoding

An evidence file is **JSON Lines**: UTF-8, one record per line, each line a JSON
object. Producers SHOULD write each line in canonical form (section 5.1). A file holds
exactly one chain.

A line ends at a line feed (U+000A) and nowhere else. A carriage return (U+000D) directly before
that line feed belongs to the line end. Anywhere else in a line a carriage return MUST be rejected.
U+2028, U+2029 and U+0085 inside a text value are ordinary characters and do not end a line, so
readers MUST split a file at U+000A only. A line that is empty or holds only whitespace MUST be
rejected.

Bytes after the last line feed are read as a line only if they are a closed object: they begin
with `{`, and the `}` that closes that object, counting brackets outside text values, is the last
byte. A verifier MUST then report that the final line feed is missing. Any other bytes after the last
line feed are not a record: a reader MUST NOT read them as one, and a verifier MUST report that they
are there. A producer writes a record and its line feed in one write, so such bytes are a write that
was cut, or a copy taken while the file was being written. A part of a record is never a closed
object, so a write that was cut is never read as a record.

An evidence file MAY be stored or sent compressed with gzip (RFC 1952). Every rule in this document
applies to the decompressed bytes. A verifier need not read gzip. One that does not MUST say that the
file is compressed, and MUST NOT report it as a damaged evidence file or give a verdict on it.

A verifier MAY stop reading a file after a number of problems. It MUST then report the file as not
verified, and say where it stopped.

Integers MUST be within +/-(2^53-1). Values that may exceed this (nanosecond
timestamps, 64-bit ids) MUST be encoded as strings. Floating-point NaN and
Infinity MUST NOT appear. A field the schema types as `integer` MUST be written as an integer:
digits, with a minus sign only before a number that is not zero, and no fraction or exponent. A
verifier MUST reject `1.0`, `1e0` or `-0` there, in every such field.

A record MUST NOT be nested more than 128 levels deep. The record itself is level 1, and every
object or array inside another adds one level. Readers MUST reject a deeper record.

Readers MUST reject a line in which an object has the same key twice: parsers
disagree on which value wins, so such a line could mean one thing to one verifier and
another to the next. Readers MUST reject NaN and Infinity, and MUST read a number
written without a fraction or exponent but beyond +/-(2^53-1) as an IEEE-754 double,
because JCS writes large whole-number doubles that way (3e18 is `3000000000000000000`). Readers
MUST reject such a number unless its text is exactly the JCS spelling of that double. So each such
double has one accepted spelling. `9007199254740993` is rejected: it reads as the double
`9007199254740992`, and a reader with exact integers would see another value than the one that was
hashed.

Unknown top-level fields MUST be prefixed `x-`; verifiers MUST ignore them
semantically (they are still covered by the record hash).

## 4. Records

Every record has these chain fields:

| Field | Type | Meaning |
|---|---|---|
| `spec_version` | `"1.0"` | Format version, `major.minor` (section 9). |
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
| `agent_identity` | | v1.0. The agent's identity in a directory: `provider` (e.g. `entra` for a Microsoft Entra Agent ID), at least one of `app_id` (application or client id), `object_id` (the agent identity's object id) and `id` (for a directory with one kind of identifier), and optionally `blueprint_id`, `tenant_id` and `name`. Directories log different identifiers for the same agent (Agent 365 records in Microsoft Defender's `CloudAppEvents` carry an agent's app id, Defender's `AgentsInfo` inventory its object id), so each says which it is. Joins evidence to the directory's own logs of that agent. |
| `sandbox_id` | | Container / VM / sandbox the agent runs in. Joins to infrastructure logs. |
| `model` | | `provider`, `name` (requested), `version` (as reported by the provider), `params` (sampling). |
| `system_prompt_hash` | | Digest of the system prompt, for quick comparison across runs. |
| `context[]` | | Model input segments, each with `source` (section 7), optional `role` / `name`, and redactable `content`. With `context_base`, only the segments added since an earlier call (section 6.10). |
| `context_base` | | v1.0. `{seq, segments}`: this call's context starts with the first `segments` segments of the full context of the `llm_call` at `seq`, followed by `context[]` (section 6.10). |
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
| `sig_alg` | `"ed25519"`, or `"ecdsa-p256-sha256"` (ECDSA over P-256 with SHA-256, for key stores without Ed25519). A later minor version may add an algorithm (section 9). |
| `public_key` | Base64 of the raw public key: 32 bytes for Ed25519, the 65-byte uncompressed SEC1 point (`0x04` \|\| X \|\| Y) for P-256. |
| `key_id` | `ed25519:` or `p256:`, then the first 16 hex digits of SHA-256(raw public key). A later algorithm uses its own prefix. |
| `signature` | Signature over the signing payload (section 6.3), base64 with padding and with any unused bits of the last character zero. Verifiers MUST reject any other spelling, which would change `record_hash` without the key. Ed25519: 64 bytes. P-256: the 64 bytes r \|\| s, big-endian, with s at most n/2 (section 6.3). |
| `next_key` | Optional. `{sig_alg, public_key, key_id}`: hands the chain over to this key (section 6.7). |
| `timestamp_token` | Optional RFC 3161 TimeStampToken (DER, base64 spelled as for `signature`) whose message imprint is SHA-256 of the signature bytes. |

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
2. Remove the value and the salt of every redactable field (section 5.3), keeping its `*_hash`.
3. `record_hash = "sha256:" + hex(SHA-256(JCS(result)))`.

### 5.3 Redactable fields

| Location | Value field | Digest field |
|---|---|---|
| `context[i]` | `content` | `content_hash` |
| `output` | `content` | `content_hash` |
| `tool_calls[i]` | `arguments` | `arguments_hash` |
| `tool_calls[i]` | `result` | `result_hash` |

In v1.0 every value has its own salt: `*_salt` is 16 random bytes, base64 encoded, and
`*_hash = "sha256:" + hex(SHA-256(salt bytes || JCS(value)))`. Without a salt, a short value (an
amount, a yes or no, an email address) could be found again from its digest by trying likely values.
Producers MUST draw a new salt for every value. Before v1.0 the digest was
`"sha256:" + hex(SHA-256(JCS(value)))`, with no salt, and verifiers MUST still accept it in v0.1 and
v0.2 records.

Producers MUST write the digest,
and SHOULD write the value. A producer MAY omit a value it considers too large to
store; it then MUST list it in the top-level `x-omitted` array (e.g.
`"context[2].content (5242880 bytes)"`), so an omitted value is distinguishable
from one redacted later. Anyone holding the evidence MAY later delete the value
and its salt, leaving the digest, and the chain still verifies. Whoever redacts MUST delete the salt with the
value, and a verifier SHOULD warn about a salt left without its value. An omitted value keeps its salt,
so the holder of the original can still check it: a value too large to store is not one anyone could
guess. A value disclosed later is checked with its salt, disclosed with it. This allows sharing evidence with
a third party without disclosing prompts, customer data or tool output, while
still letting them check the value if it is disclosed separately.

A `*_salt`, wherever it is present, MUST be the canonical base64 of its bytes, and a verifier MUST
reject any other text there. A `*_salt` without its `*_hash` is an error. A verifier MUST reject the
same salt on two values of one record. It does not look for the same salt in two records, and MUST NOT
report that as an error: a producer that repeats a salt weakens only its own redaction. A verifier SHOULD warn
when a value listed in `x-omitted` has no salt, because its original can then no longer be checked.
A verifier MUST report how many values of a file are redacted.

## 6. Integrity

### 6.1 Chain

For every record:

- `seq` is the previous `seq + 1` (the first is 0).
- `prev_hash` equals the previous record's `record_hash`.
- `record_hash` recomputes per section 5.2.
- Every present redactable value matches its digest. In a v1.0 record, a redactable value without
  a salt is an error.
- `chain_id` is constant.

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

When keys are pinned, a file with no checkpoint signed by a trusted key MUST be reported as an
error: a pinned key that signed nothing proves nothing.

A pinned key is given as the base64 of the raw public key, in its one canonical spelling. A verifier
MUST refuse a pin in any other spelling before it verifies anything. Space and a line end around the
text are not part of it.

A verifier MUST refuse an Ed25519 public key of small order (a point that 8 times itself gives the
identity), as a pinned key, as a checkpoint's `public_key` and in `next_key`. For such a key a
signature that verifies can be written without any private key.

### 6.5 Known limits

Records after the last checkpoint are covered only by the hash chain. Verifiers
MUST report how many trailing records are unsigned. Removal of complete trailing
checkpoint groups cannot be detected from the file alone: a file cut back to any
earlier checkpoint verifies. Keeping the latest checkpoint elsewhere (section 6.6),
a transparency log, or a separate WORM store closes this gap.

Redaction is a change that verifies: anyone holding the file can remove a redactable value and its
salt (section 5.3). The digest stays, so no other value can take its place.

The salt of a value that is not in the file, because the producer omitted it or someone redacted it
later, is not covered by the record hash: redaction has to be able to remove it. Someone who holds
the file can change, remove or add such a salt, and the file still verifies. They cannot make another
value pass for the recorded one. They can make the true value fail its check, or make it impossible
to check. Whoever keeps the original of an omitted value SHOULD keep its salt with it.

Spacing between tokens, the order of keys, an escape in place of a character, and the spelling of a
number outside an `integer` field can change without changing the canonical bytes, so the bytes of
a line are not protected, only its values.

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
someone who controls the agent cannot have different records signed for a range that was already signed.
They can still have new checkpoints signed while in control, over records that are not signed
yet, and a key store used directly applies none of these rules.

A chain is signed by one key at a time. To change keys, the producer writes a
checkpoint signed by the current key with `next_key` naming the new one. Every later
checkpoint MUST be signed by the key named in the most recent `next_key`, or, if
there is none, by the key that signed the chain's first checkpoint. In a v0.2 record,
a checkpoint signed by any other key MUST be reported as an error, with or without
pinned keys. In a v0.1 record it MUST be reported as a warning.

Verifiers MUST check that `next_key.key_id` matches `next_key.public_key`, and that
`next_key.sig_alg` is the algorithm of that key.

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

### 6.9 Timestamps

A checkpoint's `ts.wall` comes from the producer's clock. A `timestamp_token` adds a
time that does not: an RFC 3161 timestamp authority (TSA) signs that the checkpoint's
signature existed at that time. Verifiers that check tokens MUST report a token as an
error unless all of these hold:

- its message imprint is the hash of the checkpoint's `signature` bytes (base64-decoded);
- the TSA's signature over the time-stamp info is valid;
- the TSA's certificate has the time-stamping extended key usage, marked critical, and
  chains to a root the verifier trusts.

Verifiers SHOULD warn when `ts.wall` is more than 5 minutes after the token's time (the
producer's clock was fast), or when the token is much later than `ts.wall` (the time is
proven only from the token on). A verifier that cannot check tokens MUST say so rather
than count them as checked. Every record a timestamped checkpoint covers existed no
later than the token's time.

A `timestamp_token`, when present, MUST be a non-empty string. The token is outside the signing
payload (section 6.3), because it is made over the signature. So the token of the last checkpoint
can be removed by someone who holds the file. One that is put in or swapped is checked like any
other, and a token that fails is an error.

### 6.10 Context that records only what changed

A model call usually sends the whole conversation again, so recording each call's full context makes
a run's evidence grow with the square of its length. In v1.0 a producer MAY record only the segments
added since an earlier call of the same run: `context_base` names that call by `seq` and says how many
of its segments come first, and `context[]` holds the rest. The *full context* of a call is the first
`segments` segments of the base call's full context, followed by its own `context[]`. A call without
`context_base` is its own full context.

A verifier MUST report an error unless the base is an earlier `llm_call` in the same file, of the same
`run_id`, whose full context has at least `segments` segments. `context_base` on any other event is an
error. Readers that analyse context (detection rules, reports) MUST work on the full context, looking the
base up by chain and `seq`, never by `seq` alone, since records of several chains may be read together.
A small file can point many calls at one large context, so a reader MAY limit how much context it carries
over, and MUST then mark each call whose context it cut short rather than present it as complete. Redacting a segment of a base call redacts it in every
call built on it, as it is one value. `context_base` MUST NOT appear in records before v1.0.

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
conventions, now kept in the open-telemetry/semantic-conventions-genai repository. Field
correspondence (informative, check the current version there):

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

`spec_version` is `major.minor`. The major version changes on any change that a verifier of the
previous version would get wrong: hashing, signing, required fields, or the meaning of a field.
Verifiers MUST reject a major version they don't implement.

A minor version only adds what an older verifier can safely skip: a new top-level field, a new
`event_type`, or a new signature algorithm. A verifier MUST read a record of a newer minor version of a
major version it implements, as far as it understands it:

- A field or event type it doesn't know is covered by the record hash, so it can't be changed unseen,
  but its meaning is not checked. The verifier MUST report it as not checked.
- A checkpoint signed with an algorithm it doesn't know proves nothing to it: the records it covers
  MUST count as unsigned, never as valid. When the user pinned trusted keys, the verifier MUST report
  them as an error: it cannot show that a trusted key vouches for them. A chain signed by a known key
  moves to a key of another algorithm only by a hand-over (`next_key`) that key signed.

In a record of a version the verifier implements, an unknown field or event type is an error. Fields
of nested objects (context segments, tool calls, approvals, egress) change only with a major version.

v1.0 adds salted digests (section 5.3), `context_base` (section 6.10) and `agent_identity`, and fixes
the format: from v1.0 on, the major version changes on any change older verifiers would get wrong.
A v1.0 verifier verifies v0.1 and v0.2 files as they are. A chain MAY move to v1.0 part-way and MUST
NOT move back. A record before v1.0 MUST NOT carry a salt, `context_base` or `agent_identity`.

v0.2 adds P-256 signatures, key hand-overs (`next_key`) and `heartbeat` events. Hashing and every v0.1
field are unchanged, so a v0.2 verifier verifies v0.1 files as they are. A chain MAY
move from v0.1 to v0.2 part-way (a recorder upgraded on a running chain), and MUST NOT
move back. A v0.1 record MUST NOT use P-256, `next_key` or `heartbeat`.

In November 2026 this document was made explicit in places where it did not decide, with no new
version: how a line ends, blank lines, bytes after the last line feed, whole numbers beyond 2^53,
nesting, integer fields, gzip and a stop after many problems (section 3), salts (section 5.3), keys
of small order, the spelling of a pinned key and files with no trusted checkpoint (section 6.4), `next_key.sig_alg` (section 6.7) and the form of `timestamp_token`
(section 6.9). Nothing a conforming producer writes is read differently. A file changed by hand in
one of these ways, which an earlier verifier accepted, is rejected. A file whose last write was cut
is no longer rejected for that reason alone: the cut bytes are reported and not read.
