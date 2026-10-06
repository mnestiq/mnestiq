# Changelog

## Unreleased (0.2.0)

Evidence format v0.2. Files written by 0.1 still verify unchanged.

- Signing outside the agent. `Recorder(signer=...)` takes any signer:
  - `SignerClient` and `mnestiq signer init` / `serve`: a signing service under its own
    account. It signs only checkpoints for its own key, close to its own clock, and per
    chain only forward, so someone in control of the agent cannot have history signed
    again. It logs every signature.
  - `AzureKeyVaultSigner`: the key stays in Azure Key Vault, only a SHA-256 is sent.
    Install with `pip install "mnestiq[azure]"`.
- P-256 signatures (`ecdsa-p256-sha256`) next to Ed25519, for key stores without Ed25519.
  Only low-s signatures are valid, so each checkpoint has one valid signature per key.
- Signed key hand-overs: `Recorder.rotate_signer` writes a checkpoint naming the next key.
  A key change without one is now an error, pinned keys or not.
- Every signature from a signer is checked before it is written. If the signer is down, the
  agent carries on and signing is retried after `retry_after` seconds.
- `mnestiq keygen --alg p256`; `verify` shows key hand-overs.
- Heartbeats: `Recorder(checkpoint_interval=...)` writes and signs a `heartbeat` event when
  nothing was signed for that long, so a stopped recorder is not mistaken for a quiet agent.
  `verify` warns about silences longer than the heartbeats allow (`Report.quiet`).
- RFC 3161 timestamps: `Timestamper()` gets a token from DigiCert, then Sectigo, for each
  checkpoint and checks it before writing it. `verify` now checks every token (covers this
  signature, the authority's signature, certificate chain and key usage) instead of skipping
  them, reports the proven time and warns when the agent's clock disagrees. `--tsa-root`
  trusts other authorities. Install with `pip install "mnestiq[timestamps]"`.
- Evidence is read strictly: a line with a duplicate key, `NaN` or `Infinity` fails
  verification, so no line can mean different things to different parsers. Large
  whole-number doubles (JCS writes 3e18 as `3000000000000000000`) now verify; before, such a
  record failed with a canonicalization error.
- Canonical JSON is tested against the RFC 8785 test vectors and, with Node.js installed,
  against the RFC's JavaScript reference on thousands of random values.
- A public threat model (`docs/threat-model.md`) with one test per attack
  (`tests/test_attacks.py`), and a break-it kit (`examples/break-it`): a signed, timestamped
  incident file to try to alter without `verify` noticing.

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
