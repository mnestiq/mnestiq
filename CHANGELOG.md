# Changelog

## Unreleased

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
