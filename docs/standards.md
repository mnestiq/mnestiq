# How the evidence format relates to other standards

Checked in October 2026, before the format was fixed as v1.0. The drafts below change often: the
dates and revisions say what was read. Nothing here required a change to hashing, signing or required
fields. Two findings did change v1.0 before the freeze, so later additions won't break it:

- **Minor versions.** A verifier reads a newer minor version (1.1, 1.2) as far as it understands it,
  instead of rejecting it, and reports what it could not check (SPEC section 9).
- **Signature algorithms.** The list of algorithms is open. A checkpoint signed with an algorithm a
  verifier doesn't know counts as unsigned there, never as valid. A post-quantum algorithm (such as
  ML-DSA) can then arrive in a minor version.

## SCITT (RFC 9943)

SCITT, Supply Chain Integrity, Transparency and Trust, is an IETF Proposed Standard (RFC 9943, June
2026). An issuer signs a statement (COSE_Sign1, CBOR) and registers it with a transparency service,
which returns a receipt: a signed inclusion proof in an append-only log. The REST API for registering
statements and fetching receipts is draft-ietf-scitt-scrapi (revision 11, June 2026, with the IESG).

Evidence can be registered with a SCITT service **without changing the format**. A checkpoint's
`record_hash` is SHA-256 over the canonical checkpoint, signature included, so it can be the payload of
a COSE hash envelope (RFC 9995) registered as a signed statement, with the chain id as its subject. The
receipt proves the checkpoint existed at registration time to anyone who trusts the service. That
closes the truncation gap (SPEC section 6.5) the way a head file does, but with the record held by a
third party.

Two things to know:

- COSE signs a different structure from our checkpoint payload, so the issuer signs a second time. The
  checkpoint's own signature is not reused.
- A receipt arrives after the checkpoint is written, so it can't sit inside the hashed record. Receipts
  belong in a file beside the evidence, like the head file.

Our checkpoints use the same Merkle tree (RFC 9162, SHA-256) that COSE receipts use.

Related: draft-emirdag-scitt-ai-agent-execution (revision 01, October 2026, individual) profiles SCITT
for records of agent actions, with a canonical JSON payload inside COSE_Sign1. It is the closest
effort to this format.

## Agent action receipts

**draft-sahu-agent-action-receipts** (revision 00, August 2026, individual, Informational) defines a
JSON Lines log of signed receipts, one per agent action: `step_id`, `action_id`, `params`, `success`,
`ts_ms`, an optional `actor` and `prev_hash`, with an Ed25519 signature on each receipt in hex. It has
no Merkle tree, checkpoints, redaction or provenance of model input. Its canonical form is its own, and
adopting RFC 8785 is listed as an open issue.

**draft-marques-asqav-compliance-receipts** (revision 09, September 2026, individual) is the draft that
the Asqav product implements. It profiles draft-farley-acta-signed-receipts, uses RFC 8785, signs with
ML-DSA-65 by default, and anchors receipts with RFC 3161 or OpenTimestamps.

| This format | Sahu receipts | Asqav receipts | SCITT |
|---|---|---|---|
| `chain_id` | none | `issuer_id` | statement subject (`sub`) |
| `seq` | none | `seq` (optional, from 1) | none |
| `ts.wall` (RFC 3339, microseconds) | `ts_ms` (milliseconds) | `issued_at` (RFC 3339) | `iat` (optional) |
| `prev_hash` (`sha256:` hex) | `prev_hash` (hex of the previous line's bytes) | `previousReceiptHash` (hex) | none |
| checkpoint `merkle_root` | none | none | receipt (RFC 9162 tree) |
| `signature` (base64), `sig_alg` | `signature` (hex, Ed25519) | `sig` (base64url), `alg` | COSE signature, `alg` |
| `key_id` | none | `kid` | `kid` |
| `timestamp_token` (RFC 3161) | optional anchor | `anchors` | separate |
| `agent_id`, `agent_identity` | `actor.agent` | `agentId` | issuer (`iss`) |
| `operator_id` | `actor.user` | none | none |
| `tool_calls[]` | `action_id`, `params`, `success` | `tool_name`, `result_digest` | payload |
| `approvals[]` | none | `decision`, `reason`, `policy_digest` | none |
| redactable values with salted digests | digests advised | `payload_digest` | hash envelope |
| `context[].source`, `context_base`, `egress[]` | none | none | none |

What none of them has: where each piece of model input came from (`source`), which is what makes
prompt-injection analysis possible, and the network identity (`egress`) that joins evidence to
firewall and flow logs.

Encodings differ (hash prefixes, hex or base64 or base64url, milliseconds or RFC 3339) but convert
mechanically. Our P-256 signature form (r and s, 64 bytes, low s) is the COSE ES256 form.

## OpenTelemetry

The GenAI semantic conventions now live in open-telemetry/semantic-conventions-genai, and are still in
development. SPEC section 8 maps our fields to them. They have no attribute for where a piece of
context came from.

## Possible later additions, none breaking v1.0

- Export each checkpoint as a COSE hash envelope and register it with a SCITT service, keeping the
  receipts beside the evidence.
- An `issuer` field on checkpoints (a minor version).
- A root over the whole chain on each checkpoint, which would allow consistency proofs (a minor version).
- A post-quantum signature algorithm (a minor version).
- A mapping annex to the Sahu and Asqav receipt formats.

## Sources

- https://www.rfc-editor.org/rfc/rfc9943.html
- https://datatracker.ietf.org/doc/draft-ietf-scitt-scrapi/
- https://www.rfc-editor.org/info/rfc9942
- https://datatracker.ietf.org/doc/draft-ietf-cose-hash-envelope/ (RFC 9995)
- https://datatracker.ietf.org/doc/draft-emirdag-scitt-ai-agent-execution/
- https://datatracker.ietf.org/doc/draft-sahu-agent-action-receipts/
- https://datatracker.ietf.org/doc/draft-marques-asqav-compliance-receipts/
- https://github.com/open-telemetry/semantic-conventions-genai
