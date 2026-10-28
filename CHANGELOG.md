# Changelog

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
