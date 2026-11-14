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
| `malformed-salt.jsonl` | A salt that is not base64 in its one canonical spelling. | no |
| `crlf-line-ends.jsonl` | Every line ended by CR LF. | yes |
| `blank-line.jsonl` | An empty line between two records. | no |
| `lone-cr.jsonl` | A carriage return inside a record, not directly before the line end. | no |
| `incomplete-last-line.jsonl` | The valid chain, then bytes of a next record with no line end. | yes, with an "incomplete_last_line" warning |
| `no-final-line-feed.jsonl` | The valid chain without the LF that ends its last line. | yes, with a "no_final_newline" warning |
| `integer-with-fraction.jsonl` | An integer field (`step_id`) written `1.0`. | no |
| `integer-minus-zero.jsonl` | An integer field (`seq`) written `-0`. | no |
| `large-numbers.jsonl` | Whole numbers past 2^53 - 1, written as canonical JSON writes them. | yes |
| `respelled-integer.jsonl` | One of those numbers written as a neighbouring integer that reads as the same double. | no |
| `nesting-128.jsonl` | A value nested 128 levels deep, the deepest that is read. | yes |
| `nesting-129.jsonl` | A value nested 129 levels deep. | no |

Verify every file against the trusted key in `expected.json` (`trusted_key`). Error codes are the
reference verifier's. Another verifier need not use the same names, but it must accept and reject
the same files.

The last twelve files are about how the bytes of a file are read, before any hash is checked. Read
them as bytes: a tool that splits lines at anything but LF, or that changes line ends, changes what
they show. A line that is refused is not a record, so the chain around it reports a missing record
too (`link`, `seq`, `merkle_root`). For nesting, the record itself is level 1, every object or array
inside another adds one level, and text, numbers, `true`, `false` and `null` add none.

Bytes after the last LF of a file are a line when they are a closed JSON object: they start with
`{`, and the `}` that closes that object is the last byte (`no-final-line-feed.jsonl`). That line is
read like any other. Any other bytes there are a fragment and are not read
(`incomplete-last-line.jsonl`).

`expected.json` also holds a worked example for one record: its salt, the canonical JSON (RFC 8785)
of a value, the salted digest, the canonical JSON of the hashed form, and the resulting
`record_hash`. Check those first: most disagreements between implementations are in canonical JSON.

The signing keys are derived from fixed strings in `generate.py` and published on purpose, so the
files can be rebuilt byte for byte. Never use them for real evidence.

To rebuild: `python spec/vectors/generate.py`. `--check` exits 1 if a file would change.
