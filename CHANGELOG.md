# Changelog

## Unreleased

Fixes found in a review of 1.1.0. The record format and spec version are unchanged. Some records now carry
different values: a missing model name, a role this version does not know, and an answer that is not all in its
record are each written one way on every path. The rules find planted links and images they used to miss.
Commands report the library's own errors in one line.

### Stricter reading of evidence files

A test of the verifier against about 148,000 changed files found no way to change a signed value or forge a
signature and keep VALID. It did find ways to respell a file so that another program reads it differently, and
places where the spec did not decide. `spec/SPEC.md` now decides them, with no new format version, and `verify`
follows it. Nothing a recorder writes is read differently, with the one exception in the first point.

- **A record is a line that ends with a line feed.** A last line with no line feed is read only if it is a
  whole record, and `mnestiq verify` then warns `no_final_newline`. Anything else after the last line feed is
  a part of a record: it is not read, and `mnestiq verify` reports it (warning `incomplete_last_line`, and
  `incomplete_tail_bytes` in `--json`) and gives its verdict for the lines before it. Before, a file cut in
  the middle of a write was INVALID. A file from a recorder that crashed in the middle of a write now
  verifies, with that notice.
- A blank line is an error. It used to be skipped. A recorder does not continue a file that holds records and
  a blank line. A file that holds nothing but spaces and line ends is emptied and started as a new file.
- A carriage return is accepted only directly before the line feed. Anywhere else in a line it is an error.
- A whole number beyond 2^53 - 1 is accepted only in the spelling canonical JSON gives it. Before,
  `9007199254740993` was read as `9007199254740992` and the file stayed VALID.
- A record nested more than 128 levels deep is an error, and the recorder refuses to write one.
- A salt must be base64 in its one canonical spelling wherever it stands, also next to a value that is redacted
  or was left out. The same salt on two values of one record is an error. The `salt` warning no longer suggests
  that a salt left without its value is the recorder's own. New warning `omitted_salt` for a value the recorder
  left out whose salt is gone. A copy made by `mnestiq redact` gets it for each such value, since `redact`
  removes those salts, and the warning says that this is expected there.
- The schema's patterns are read as JSON Schema means them: a time or a salt with a newline after it no longer
  passes. `timestamp_token` must be a non-empty string.
- `next_key.sig_alg` must be the algorithm of the key it names.
- An Ed25519 public key of small order is refused as a pinned key, in a checkpoint and in a hand-over. For such a
  key anyone can write a signature that verifies. Thirty-two bytes that are not a point of the curve are refused
  where the key is read.
- `mnestiq verify` reads a gzip file, with a limit of 64 MiB on one unpacked line. `inspect` and `redact` say to
  unpack it first, and the dashboard lists it as not verified.
- `mnestiq redact` verifies what it reads and writes nothing from a file that does not verify.
- `mnestiq inspect` ends with a line that says whether the file verifies. Its listing was never a check, and it
  now says so. Its exit code is unchanged.
- The dashboard reuses a verdict only when the content of the file is unchanged. Before, an unchanged size and
  modification time were enough.
- New conformance vectors in `spec/vectors/` for these rules.

Two limits are now stated in the spec and in `docs/threat-model.md`. The salt of a value that is not in the file
is not signed: someone who holds the file can make the true original fail its check, and cannot make another
value pass. And redaction is itself a change that verifies.

The test suite gained 61 tests for checks of the verifier that no test covered. They were found by removing each
check in turn and seeing whether a test failed.

### Changes you may notice

- `mnestiq` commands report a `RecorderError`, `SinkError`, `SignerError` or `TimestampError` as one `error:`
  line and exit with code 2, as for a bad argument. Before, these ended in a traceback with exit code 1, the
  same as INVALID.
- `mnestiq verify` and `mnestiq inspect` write characters that change the direction of text as escapes, as they
  do line breaks. `mnestiq verify` cuts a field name it quotes from a file to 200 characters.
- A request that names no model is recorded with model `<unknown>` on every path. The SDK integrations wrote
  `None` and the API proxy wrote `unknown`.
- An OpenAI `role: "function"` message, the older form of a tool result, is recorded as `tool_output`, or as
  the source set for that tool. A chat role, Responses item type, or Anthropic role or content block that this
  version does not know is recorded as `unknown`, which the rules treat as untrusted. Before, most of these
  counted as the user's words.
- A Chat Completions answer with several choices still has only the first recorded. The record is now marked
  `output_captured: "partial"`, with a `capture_note` that says so. This holds for streams too.
- The API proxy reads answers and streams with the same code as the SDK integrations, so the same answer gives
  the same record on both paths. It now marks an answer it holds part of as `"partial"` rather than `false`,
  keeps streamed output up to `max_content_bytes` as the SDK path does, and gives a stream that ends before its
  last event the `error` the SDK path gives.
- `instrument_egress()` refuses a single string for `ignore_hosts` or `stamp_hosts` with `TypeError`. It used to
  read one as a set of letters. Names in these lists are matched without regard to case or a trailing dot.
- The signing service serves at most 256 connections at once, 32 of them still proving the token, and closes a
  connection idle for 300 seconds. See [docs/signing.md](docs/signing.md).
- The rules read a host with a port (`evil.example:8443/c`) correctly. `MNQ-001` also flags a
  planted link whose host is a name under a host from untrusted content, such as data put in a label.
- A host counts as its parent domain's except under a shared suffix where anyone can have a name, such as
  `co.uk` or `github.io`. Before, a name the user gave there could hide another site under the same suffix. The
  list is built in and is not the full public suffix list.
- `MNQ-001` is now quiet for a link to a name under a site the user or the system prompt named, as `MNQ-005`
  and `MNQ-006` already were. If the user names `acme.example`, a planted link to `cdn.acme.example` is not
  flagged. In 1.1.0 it was.
- An IP address has no parent domain. Before, a number in the user's words, such as a version `1.10`, could
  hide an image loaded from `203.0.1.10`.
- The `MNQ-000` text for a partly captured answer no longer names a cause, since there is now more than one.
- `MNQ-005` finds images in more forms: the `img`, `image`, `video`, `audio`, `source` and `input` tags with
  `src`, `srcset`, `poster` or `href`, the markdown references `![alt][]` and `![alt]`, and alt text that holds
  brackets.
- When the rules reach their work limit while judging an approval, `MNQ-000` is reported on that approval, not
  on the next one.
- The dashboard's server runs the rules over each whole file, and the page shows what they find. In a file too
  large to show whole, findings on earlier records are listed apart, up to 20,000, with a count of the rest. If
  the server cannot run them, the page runs its own copy on the records shown and says so.
- The dashboard marks a record sealed only by a checkpoint the verifier checked with no error. It calls a record
  altered only for a hash, link, Merkle root or signature that does not match, and labels other problems by kind.

### Fixed

- Error text in egress events, and the API proxy's log, mask query values with secret looking names in each
  form clients quote them, as the `url` field does.
- A stream closed early while egress capture is on is recorded where it ends, and its run ends. Events put aside
  while the chain was busy keep their order, and are written at process exit if the recorder was never closed.
  Events put aside from threads with no run of their own are capped at 4,096. Past that, each one is dropped and
  counted in `recorder.failures`.
- With `instrument_egress()`, the run id headers no longer reach a host that is not stamped, such as one a
  redirect leads to, and the caller's own request object is left as it was. In strict mode a cancelled request
  still raises the cancellation, even when recording it fails.
- Every event the recorder writes about itself carries the agent's identity, and an empty `agent_id` no longer
  makes one fail.
- `MemorySink` holds what a file would hold, read back the way a file is read.
- A recorder refuses to carry on from a file with a salt that is not 16 bytes, signed or not.
- `mnestiq verify` looks at no more than 1,000 schema errors per record, so one crafted line no longer uses
  memory without bound. It still shows the first five.
- `mnestiq proxy --azure-key` reads the key as `signer serve` does: it gives up after 30 seconds and says what
  went wrong in words.
- `SignerClient` does not reuse a connection left idle for more than 120 seconds. After a failure it sends a
  request again only when that is safe.
- Nothing can come between a recorder's last records and its final checkpoint on `close()`.
- Before Python 3.12, a connection made within a few calls of the recursion limit could now and then go
  unrecorded without being counted. It is counted in `recorder.failures`.

## 1.1.0 (2026-11-09)

Security fixes for crafted evidence files, reported by Agentic Thinking, and for what our own testing then
found. See the [security note](docs/security-notes/1.1.0.md). In our tests, without the signing key or a
signing identity, no change to a value in a signed record stayed VALID under a pinned key. Respelling a number
or changing JSON spacing does not change a record's hash, and the last checkpoint's timestamp can be removed
(see the note). The record format and spec version are unchanged. One rule for reading checkpoints is stricter:
a signature or timestamp token must be spelled as a recorder writes it. An empty or null `timestamp_token`, or
bytes after the token, are errors too.

### Changes you may notice

- A record the rules cannot fully read is returned as `MNQ-000`, a new entry in `mnestiq.findings.RULES`.
- `mnestiq redact` refuses a malformed record, a value that does not match its digest, a field this version
  does not know, and any `x-` field other than `x-omitted`.
- The signing service refuses a hand-over to another key unless started with `--allow-handover`, and a repeat
  must be identical.
- `SinkError` is now a kind of `RecorderError`, so `except RecorderError` catches it too.
- A recorder refuses to carry on from a file whose chain or signatures do not verify, whether or not `strict` is
  set. Timestamp tokens and key pinning are checked only by `mnestiq verify`.
- `FileSink` refuses anything at the evidence path that is not a regular file: a symbolic link, FIFO, device or
  directory. Give it the real file. A link higher up the path still works. It also refuses to cut a torn line from
  a file that has another hard link.
- `mnestiq verify` warns `signed_after_restart` when records were signed only after a recorder restarted.
- `mnestiq verify` warns `resumed_without_clean_close` when a recorder resumed without a signed clean close.
  A file from an older recorder warns once.
- `findings()` returns `MNQ-000` for a model call whose output was not captured, or only partly captured.
- With a signer, a close that wrote records adds a `clean_close` heartbeat just before the last checkpoint.
- With `instrument_egress()`, threads and thread pool tasks started during a run belong to it, and `urllib` and
  `urllib3` are recorded. They are stamped only for hosts in `stamp_hosts`.
- Python audit hooks record connections the patches missed, and datagrams, name lookups and process launches as
  notes. Through a proxy, `host` is the real destination.
- `MNQ-003` also fires on a datagram or raw socket noted after untrusted content reached the model. Name lookups
  do not count. Each destination is noted once before and once after untrusted content first reaches the model, up
  to 256 per kind each time. Past the limit after that point, the rules report `MNQ-000` rather than naming the
  destination.
- The signing service limits how many chains it holds. See `--max-chains` in [docs/signing.md](docs/signing.md).
- The `error` field follows `max_content_bytes`.
- A line that is not valid JSON or JSON whitespace is an error, as is a number too large to keep.

### Fixed

- `mnestiq verify` reports any bad record as an error and keeps what it found, instead of crashing.
- The rules no longer lose findings in silence, read a number the same however it is spelled, and take bounded
  time on a crafted file. The dashboard page is in step.
- The dashboard shows malformed records as unreadable, and one bad file no longer stops the folder listing.
- `mnestiq inspect` carries on past a bad line and prints one line per record.
- Unless `strict` is set, recording does not raise into the agent once it is running, and an event that cannot be
  recorded in full is recorded and marked.
- The API proxy records a call it used to lose, or counts the failure if nothing can be written, and marks what it
  could not capture.
- The signing service and its client answer bad input with an error.
- The signing service, API proxy and dashboard no longer drop connections in a burst on Linux.
- `mnestiq verify` refuses a signature or timestamp token in any base64 spelling other than the one a recorder
  writes. An empty or null `timestamp_token`, or bytes after the token, are errors too.
- Crash recovery no longer mistakes a record whose own data has a `prev_hash` key for a damaged file.
- `HeadFile` no longer follows a link at its temporary name.

### Added

- `mnestiq.instrument_models(recorder)` records calls through the Anthropic and OpenAI Python SDKs without
  wrapping each client.
- `mnestiq signer serve --azure-key` puts the signing service's rules in front of Azure Key Vault. The service
  in front of it has been tested against a stand-in only.
- `mnestiq verify --witness` compares a file with the record the signing service keeps of each chain, and
  reports a rewritten or cut-back file as INVALID, as far as the witness reached.
- `Recorder(checkpoint_on=...)` signs right after chosen event types. `Recorder(on_damaged="new_file")` sets a
  damaged file aside and starts a new chain.
- `create(stream=True)` and the OpenAI stream helpers record their output. With `instrument_models`,
  `client.post()` to a model endpoint is recorded too, and `post(cast_to=httpx.Response, stream=True)` is recorded
  without its output. `responses.stream(response_id=...)` and a model call made inside another SDK call are not
  seen.

### Tests and documents

- New: fuzzing of evidence files through every reader (`tests/test_fuzz.py`, with a long tier in
  `tests/fuzz/run_long.py`), and hostile-input tests for every surface.
- New: `docs/claims-map.md`, the security claims we listed from our documents and the test behind each one. It
  does not cover every sentence.
- Claims the tests did not support are corrected.

## 1.0.1 (2026-10-30)

- `CITATION.cff`: GitHub shows "Cite this repository" with APA and BibTeX entries, and each release
  is archived on Zenodo with a DOI.
- The tests that read the break-it kit or the spec folder skip in the source package, which has
  neither, instead of failing. Nothing else changes: same format, same API.

## 1.0.0 (2026-10-28)

The evidence format is now v1.0 and stable: a change older verifiers would get wrong needs a 2.0, and
a 1.0 verifier reads later 1.x files as far as it understands them. Files written before 1.0 still
verify as they are. See [spec/SPEC.md](spec/SPEC.md) section 9.

### Format 1.0

- **Salted digests.** Every redactable value (prompts, tool arguments and results, answers) gets its
  own random salt, mixed into its digest. A redacted short value, such as an amount or an email
  address, can no longer be found again by hashing guesses. `mnestiq redact` removes the salt with the
  value, and `verify` warns about a salt left behind.
- **Model calls record only what changed.** Most model calls send the whole conversation again. A
  call now records the segments added since the run's previous call and points back to it
  (`context_base`), so a long run's evidence grows with its length instead of its square. Detection
  rules, the dashboard and `inspect` read the full context, and `mnestiq.context.expand` gives it to
  your own code. Turn it off with `Recorder(context_delta=False)`.
- **The agent's directory identity.** `Recorder(agent_identity={"provider": "entra", "app_id": ...,
  "object_id": ...})`, or `MNESTIQ_ENTRA_AGENT_APP_ID` and `MNESTIQ_ENTRA_AGENT_OBJECT_ID`, puts the
  agent's Microsoft Entra Agent ID on every event, the key that joins evidence to Microsoft's own logs
  of that agent. Each identifier says which it is: Agent 365 records in Defender's `CloudAppEvents`
  carry the agent's app id, Defender's `AgentsInfo` inventory its object id.
- **Room to grow.** A later 1.x version may add top-level fields, event types and signature
  algorithms (a post-quantum one, say). A 1.0 verifier reports what it could not check, and counts
  records under a checkpoint it cannot verify as unsigned, never as valid.

### Safer with hostile files

- Every field of a file replaced with a value of the wrong type is reported, never a crash, in the
  verifier, the context reader and the detection rules (a test now tries each one).
- A checkpoint signed with an algorithm this version doesn't know never hides records: they count in
  the unsigned tail, and a chain signed by a known key can move to another only by a signed hand-over.
- Readers carry earlier context within a budget, so a small file can't make the dashboard or the rules
  copy one large context thousands of times. A call cut short is marked `x-context-truncated`.
- The dashboard lists the other files when one can't be read.

### Added

- `mnestiq demo`: records a prompt-injection incident and walks through the investigation (the
  firewall connection traced to the agent step, a tampered copy caught, a redacted copy verified),
  then opens the dashboard. No API key, nothing beyond `pip install mnestiq`.
- Test vectors in [spec/vectors](spec/vectors): evidence files with the verdict each must get, and a
  worked example of the hashing, for anyone writing a verifier in another language.
- [docs/standards.md](docs/standards.md): how the format relates to SCITT (RFC 9943) and the agent
  receipt drafts, and how checkpoints can be registered with a SCITT transparency service.

## 0.5.0 (2026-10-17)

### Fewer false alarms

- MNQ-002 (auto-approval) now fires only when the approved call carries a value from untrusted
  content. An inbox agent always reads an email before it replies, so every reply a policy
  approved used to be a lead. On a normal day of 14 business emails, runs with a lead went from
  20 of 28 to 3 of 28, and every harmful run is still flagged.
- MNQ-004 ignores values under three characters, such as `r` for read access, which matched by
  chance.

### Catches more

- MNQ-006 (internal data to new recipient): data from the company's own systems (tool output
  labelled `internal`) sent to an address or host that appears neither in those systems nor in the
  system prompt, such as the price list sent to a "new customer". No injection is needed.
- An IBAN printed in groups of four ("GR96 0810 0010 ...") counts as an account number for MNQ-001.
- MNQ-004 checks numbers of four digits or more in any sensitive action, such as a credit limit of
  60000 or a refund of 2400. Shorter numbers still count only for destructive actions.
- Tools named for discounts, bank details, IBANs, payouts, credit and customer, supplier, vendor or
  payee updates count as sensitive when not marked. This matters most behind the proxy, where
  tools cannot be marked in code.

## 0.4.0 (2026-10-14)

### Added

- `mnestiq proxy`: records an agent's model calls from outside the agent, whatever language or
  framework it is written in. Point the agent's base URL at it. It reads OpenAI Chat Completions
  and Responses, Anthropic Messages, Azure OpenAI and OpenAI-compatible servers, and records
  streamed answers whole. The API key passes through and is never written down. Runs are worked
  out from a header, a trace, tool results or the conversation, and each record says which. See
  [docs/proxy.md](docs/proxy.md).

### Faster

- Recording an event takes about 0.5 ms instead of 1.2 ms, and `verify` reads about 6 MB a second
  instead of 2: each record is checked against the schema for its own kind (event or checkpoint)
  instead of both, which gives the same verdict. An invalid record now names the field that is
  wrong.

### Detection

- `MNQ-004` also covers sensitive actions the model asked for in evidence from the proxy, which
  sees the request but not the tool run. These say "requested".
- `MNQ-003` no longer counts an agent's calls to its own model API (OpenAI, Anthropic, Azure
  OpenAI, Bedrock and others) as egress after taint. The recorder already leaves those out, but
  evidence from older versions and other tools may hold them.

## 0.3.0 (2026-10-10)

Upgrading is recommended for everyone: this release includes security hardening across
verification, signing and the local tools.

### Security

- Stronger checks on RFC 3161 timestamps, the signing service, and verification with a pinned key.
- The recorder refuses to extend a chain whose earlier records no longer match.
- The dashboard needs the key printed in its link, and evidence text can no longer drive the
  terminal or the page's styling.
- Less of what the agent handles reaches logs, error messages and request headers.
- The release workflow runs the tests without access to signing or publishing.

### Changes to note

- `verify --trusted-key` reports a file with no signed checkpoints as INVALID (a pinned key that
  signed nothing proves nothing). Without a pinned key it is still a warning.
- `mnestiq dashboard` prints a link with a key, and answers only requests that carry it.

### Detection

- New finding `MNQ-005`, untrusted link in answer: the model's answer carries an image, or a
  link with data in its query, to a host that appears in untrusted content and not in the
  user's or system's words. An image is fetched as soon as the answer is shown, so this is how an
  injected instruction can leak data with no tool call at all. In `mnestiq.findings` and in the
  dashboard.
- `MNQ-004` treats more actions as sensitive by name: cancel, suspend, deactivate, terminate,
  close an account, change, modify, forward, share, invite and unsubscribe.
- Domains and links in untrusted content are matched more precisely, and quickly on long text.

### Recording

- Recording never raises into the agent: unusual values (invalid Unicode, number subclasses,
  objects that cannot be copied, cyclic data) are recorded as well as they can be, and any
  failure is counted.
- Requests and tools cancelled by a timeout are recorded, with the cancellation as the error.
- Writes are unbuffered and flushed before the head file, so a failed or interrupted write cannot
  break the chain later.
- Processes that fork, tools defined as methods, and streams finished in another task are
  handled.
- OpenAI: more Responses API output types are recorded as tool output, and Chat Completions
  custom tool calls are recorded.

### Verification

- `mnestiq.verify.ChainVerifier`: feed a chain's lines as they arrive and ask for the report at
  any point. The result is exactly that of `verify_lines` over the same lines, so a collector
  following a growing file checks only what is new.
- `verify` reports malformed records instead of stopping, and an unreachable timestamp authority
  no longer holds up checkpoints.

## 0.2.1 (2026-10-08)

### Fixed

- With outside timestamps and egress capture both on, the recorder's own request to the
  timestamp authority was captured as the agent's egress and written in the middle of a
  checkpoint. The chain broke there, and a signing service then refused every later
  checkpoint. The recorder's own signing and timestamp traffic is no longer captured, and any
  event written while a checkpoint is made now follows it. Found with a real agent.
- The signing service checks each connection's token on that connection's own thread, with a
  5 second limit. Before, one connection that said nothing held up every client after it, and
  the client waited for ever. The client's timeout now covers connecting too.
- The signing service flushes its state to disk before using it, so a power cut cannot leave
  it behind the signatures it gave.

## 0.2.0 (2026-10-07)

This release moves checkpoint signing out of the agent's process, adds independent
timestamps and liveness signals, and introduces version 0.2 of the evidence format. Evidence
written by 0.1.x continues to verify without changes.

### Highlights

- **Signing outside the agent.** Signing keys can now be held where the agent cannot read
  them: in Azure Key Vault, or in a dedicated signing service running under a separate
  account. A compromised agent can no longer copy the key or have earlier history signed
  again.
- **Independent timestamps.** Checkpoints can carry RFC 3161 timestamps from public
  timestamp authorities, and the verifier now validates them in full.
- **Liveness.** Recorders can emit signed heartbeats, so a stopped recorder can be told apart
  from an idle agent.
- **Published threat model.** Each documented attack is backed by an automated test, and a
  public challenge kit is provided for independent review.

### Evidence format 0.2

- Adds ECDSA P-256 signatures (`ecdsa-p256-sha256`) alongside Ed25519, for key stores that
  do not support Ed25519. Only low-s signatures are accepted, so every checkpoint has exactly
  one valid signature per key.
- Adds signed key hand-overs (`next_key`). A change of signing key is accepted only when the
  previous key authorised it. Any other key change is reported as an error, whether or not
  keys are pinned.
- Adds the `heartbeat` event type.
- Readers must reject duplicate object keys, `NaN` and `Infinity`, and read large whole
  numbers as IEEE-754 doubles, as RFC 8785 serialises them.
- A chain may move from version 0.1 to 0.2 part-way through, but never back.

### Added

- `Recorder(signer=...)`, accepting any signer:
  - `SignerClient`, with `mnestiq signer init` and `mnestiq signer serve`: a local signing
    service. It signs only checkpoints for its own key, only near its own clock, and per
    chain only in order. Every signature is written to an audit log.
  - `AzureKeyVaultSigner`: keys held in Azure Key Vault or Managed HSM. Only the SHA-256
    digest of each checkpoint leaves the machine. Requires `mnestiq[azure]`.
  - `LocalSigner`, for keys held in process (development and testing).
- `Recorder.rotate_signer()` for signed key rotation.
- `Recorder(checkpoint_interval=...)` and `Recorder.heartbeat()`.
- `Timestamper`, which requests RFC 3161 timestamps from DigiCert, with Sectigo as fallback,
  and validates each token before it is written. Requires `mnestiq[timestamps]`.
- `mnestiq keygen --alg p256` and `mnestiq verify --tsa-root`.
- `Report.rotations`, `Report.timestamps` and `Report.quiet`.
- Threat model (`docs/threat-model.md`), attack test suite (`tests/test_attacks.py`) and the
  break-it challenge kit (`examples/break-it`).
- Signing guide (`docs/signing.md`).

### Changed

- The verifier now validates RFC 3161 timestamp tokens (the message imprint, the authority's
  signature, the certificate chain and the time-stamping key usage) instead of reporting them
  as unchecked. It warns when the recorder's clock disagrees with the timestamp.
- The verifier warns about gaps longer than the configured heartbeat interval allows.
- Every signature returned by a signer is verified before it is written to evidence. If a
  signer is unavailable, recording continues and signing is retried after `retry_after`
  seconds.
- A recorder that resumes an existing chain with a different key now refuses to start, rather
  than producing evidence that would fail verification.
- The dashboard uses colour only for untrusted input, findings and tampering.

### Fixed

- Records containing large whole-number floating-point values (for example `3e18`) failed
  verification with a canonicalisation error.

### Security and build

- Canonical JSON is tested against the RFC 8785 test vectors and cross-checked against the
  RFC's JavaScript reference implementation.
- Releases carry a GitHub build provenance attestation, verifiable with
  `gh attestation verify`.
- All GitHub Actions are pinned to commit hashes, Dependabot is enabled, and CI audits
  dependencies with `pip-audit`.

### Upgrading

- Existing code continues to work. `signing_key=` is still accepted and is equivalent to
  `signer=LocalSigner(key)`.
- Verifiers older than 0.2.0 reject version 0.2 records. Upgrade verifiers before recorders.
- For production deployments, move signing keys to Azure Key Vault or the signing service.
  See `docs/signing.md`.

## 0.1.1

- The recorder refuses records the verifier would reject, such as an unknown `event_type`,
  instead of writing them into the signed chain.
- `FileSink` allows one writer per evidence file. A second recorder on a file that is
  already being written raises `SinkError` instead of interleaving two chains.
- Opening a file that holds data other than Mnestiq evidence raises a clear error.

## 0.1.0

First public release.

- Evidence format v0.1: JSON Schema and specification, RFC 8785 canonical JSON,
  SHA-256 hash chain, Ed25519-signed Merkle checkpoints (RFC 9162), redactable fields.
- Recorder with `FileSink` and `MemorySink`: crash recovery for torn writes, size cap for
  large values, non-strict and strict failure modes, `run.bind` for worker threads.
- Capture for the Anthropic and OpenAI Python SDKs (sync and async; Chat Completions and
  Responses APIs).
- Egress recording for httpx, requests and raw TCP connections, with run identity headers.
- `mnestiq` CLI: `verify`, `inspect`, `redact`, `keygen`, `dashboard`.
- Findings `MNQ-001` to `MNQ-004` in the dashboard and as `mnestiq.findings`; tools can be
  marked `sensitive`.
- `HeadFile` and `verify --head`: keep the latest checkpoint elsewhere so a file cut back to
  an earlier checkpoint is detected.
- Local dashboard with a connection finder; it follows the newest file and run as agents write.
