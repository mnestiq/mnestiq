# Test vectors for the evidence format v1.0

Evidence files with the verdict a verifier must give each one, for anyone writing a verifier or a
producer in another language. `expected.json` lists every file with what it shows, whether it must
verify, and the error and warning codes the reference verifier (`mnestiq verify`) reports.

| File | What it shows | Verifies? |
|---|---|---|
| `valid.jsonl` | A complete signed chain. The second model call records only what changed (`context_base`). | yes |
| `redacted.jsonl` | Every redactable value removed with its salt. | yes, with a "redacted" warning |
| `edited-content.jsonl` | A tool result edited, its digest left as it was. | no |
| `edited-record.jsonl` | An approval rewritten, `record_hash` left as it was. | no |
| `rewritten-chain.jsonl` | The same edit with every hash recomputed: the signed Merkle root no longer matches. | no |
| `deleted-record.jsonl` | One record removed. | no |
| `bad-context-base.jsonl` | A model call pointing back to a record that is not a model call. | no |
| `missing-salt.jsonl` | A 1.0 value with an unsalted digest. | no |
| `other-key.jsonl` | A consistent chain signed by a key that is not pinned. | no |
| `newer-minor.jsonl` | Written by a later minor version (1.1) with a field 1.0 doesn't know. | yes, with a "newer_version" warning |

Verify every file against the trusted key in `expected.json` (`trusted_key`). Error codes are the
reference verifier's. Another verifier need not use the same names, but it must accept and reject
the same files.

`expected.json` also holds a worked example for one record: its salt, the canonical JSON (RFC 8785)
of a value, the salted digest, the canonical JSON of the hashed form, and the resulting
`record_hash`. Check those first: most disagreements between implementations are in canonical JSON.

The signing keys are derived from fixed strings in `generate.py` and published on purpose, so the
files can be rebuilt byte for byte. Never use them for real evidence.

To rebuild: `python spec/vectors/generate.py`. `--check` exits 1 if a file would change.
