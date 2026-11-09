# Threat model

What Mnestiq evidence protects, against whom, what it catches, and what it does not do.
Every attack in the table below has a test that carries it out, named in its row, most of them in
`python/tests/test_attacks.py` (run `pytest tests/test_attacks.py -v`), and you can try your own on the
[break-it kit](../examples/break-it/README.md). The Evidence Vault and the Workbench are separate
services, so what this page says about them has no test in this repository.

## What is protected

The record of what an AI agent saw, decided and did: model calls with the provenance of
every piece of input, tool calls, approvals and outbound connections. The goal is that
after an incident, an investigator, an insurer or a court can rely on that record, even if
someone with access to the agent's machine wanted it to say something else.

## Who we defend against

| | Who | Can |
|---|---|---|
| **Insider or intruder after the fact** | Someone with write access to stored evidence | Edit, delete, reorder, truncate or replace files |
| **A hijacked agent** | Someone in control of the agent process (prompt injection, a compromised dependency) | Everything the agent's account can do, while in control |
| **A thief of keys** | Someone who copied a signing key | Sign anything with it |
| **A dishonest or breached vault** | The operator of the Evidence Vault, or someone who took over its web process | Change what the vault stores and says |

## How it works, briefly

Records are hash-chained (each includes the hash of the one before) and every 100 records,
or on a timer, a **checkpoint** signs a Merkle root over them. Content such as prompts can be
removed for sharing without breaking the chain. The format is in [SPEC.md](../spec/SPEC.md).

## What is caught

| Attack | Caught by | Test |
|---|---|---|
| Edit a record | Its hash no longer matches | `test_a1` |
| Edit, and fix every hash and link | The checkpoint signature no longer matches | `test_a2` |
| Delete or reorder records | Sequence numbers and links | `test_a3`, `test_a4` |
| Swap a prompt or tool result | Each value is committed by its own digest | `test_a5` |
| A line that means two things to two parsers (duplicate keys, NaN) | Strict reading: refused | `test_a6` |
| Cut the file back to an earlier checkpoint | The head kept elsewhere (`--head`), or the Evidence Vault | `test_a7` |
| Rewrite everything and sign with your own key | The pinned key (`--trusted-key`) | `test_b1` |
| Switch keys part-way | A key change needs a hand-over signed by the old key; error even without a pin | `test_b2` |
| Hand over to your own key, from your own key | A hand-over vouches only if its signer was trusted | `test_b3` |
| Make a second valid P-256 signature (malleability) | Only low-s signatures are valid | `test_b4` |
| Take over the agent and get history signed again | The signing service signs each chain only forward, and only checkpoints | `test_b5` |
| Copy the key from the agent's machine | With the signing service or Azure Key Vault, the agent never holds it | `test_b6` |
| Set the clock back | The signing service refuses times far from its own clock; RFC 3161 timestamps from DigiCert or Sectigo give a time nobody on the machine controls | `test_c1`, `test_c2` |
| Move a genuine timestamp to another checkpoint | A token covers one signature only | `test_c2` |
| Stop the recorder | Heartbeats: a gap in the file is reported once the recorder writes again, and the vault alerts while it happens. A recorder that never restarted leaves no gap in the file | `test_d1` |
| Recover a redacted value by hashing guesses (an amount, an email address) | Since format 1.0 each redactable value has its own random salt, removed with the value. `system_prompt_hash` stays a plain digest, so a guessed system prompt can be confirmed from it | `test_format_v1.py::test_the_same_value_gets_a_different_digest_each_time` |
| Cover rewritten records with a checkpoint "signed" with an algorithm the verifier doesn't know | Such records count as unsigned, and with a pinned key they are an error. A chain signed by a known key can't switch without a signed hand-over | `test_review_fixes.py::test_an_unknown_algorithm_checkpoint_cannot_hide_a_rewritten_tail` |
| Point a model call at another call's context, or mix two files so the rules read the wrong one | The verifier checks every `context_base`, and readers look the base up by chain and run | `test_format_v1.py::test_a_wrong_base_is_an_error`, `test_review_fixes.py::test_records_of_two_chains_mixed_keep_their_own_context` |
| A small file that makes readers copy one large context thousands of times | Carried context is budgeted, and a call cut short is marked, never shown as complete | `test_review_fixes.py::test_a_context_bomb_is_cut_off_not_expanded` |
| A small file built to make a reader's patterns or lookups take minutes | Patterns take time in proportion to their text, and lookups have a work limit: what it stops comes back as MNQ-000, here and on the page | `test_redteam.py::test_quadratic_values_against_context` |
| A number respelled (`4100` as `4100.0`) so the rules miss it while the hash stays the same | Numbers read as one text however the file spells them, in Python and on the page | `test_redteam.py::test_respelled_number_keeps_mnq004` |
| A long run whose context can't be carried, so a finding quietly disappears | The rules report the call as MNQ-000: its context is incomplete | `test_redteam.py::test_carry_budget_marks_the_call_as_incomplete` |
| Change a value, then redact it so the copy verifies | `redact` checks each value against its digest and refuses the file | `test_redteam.py::test_redact_refuses_a_changed_value` |
| Redact a record holding a field this version does not know | `redact` refuses and says to upgrade: what such a field holds must not reach the copy | `test_redteam.py::test_redact_refuses_an_unknown_field_of_a_newer_minor` |
| A damaged or crafted file meant to crash the verifier, the rules or the dashboard | Every field of a valid file, and every optional or extension field it could carry, on appended lines too, is tried with values of the wrong type: each is reported as an error with everything found so far kept. A record the rules cannot read comes back as an MNQ-000 entry instead of being passed over, the dashboard shows it as text only, and `redact` refuses the file | `test_hostile_input.py` |

## The Evidence Vault

The vault keeps an independent copy of each checkpoint and returns a signed receipt, so a
file cut back or rewritten on the agent's machine disagrees with it. Trusting the vault
would only move the problem, so:

- Every receipt goes into an **append-only Merkle log** (as in Certificate Transparency,
  RFC 9162). Clients check each signed log head against the last one they saw, with a
  consistency proof, and check their own receipts are in it. A vault that drops, changes or
  forks its history is caught by any customer.
- The vault's key is in a **separate signer process**. It refuses to backdate a receipt, to
  reuse a log position, or to sign a log head that differs from the receipts it signed. Someone
  who takes over the vault's web process can stop it, not rewrite it.
- Each log is **anchored hourly** with an RFC 3161 timestamp, and customers can copy the anchors
  into **write-once storage they own** (Azure immutable Blob, S3 Object Lock).
- The vault raises alerts for rewrites, rollbacks, key changes without a hand-over, **new
  chains**, and chains that **go quiet**.

## What it does not do

These are limits by design. We would rather you hear them from us.

1. **Lies told while in control.** Whoever controls the agent while it runs can make it record
   false events, and they are signed like true ones (`test_e1`). Evidence is tamper-evident
   after it is written, not truthful at the source. Our answer is outside the file: the
   Mnestiq Workbench compares the agent's account with records the agent does not control.
2. **Signatures while in control.** Someone in control of the agent can ask the signing service
   or Key Vault for signatures on new checkpoints. They cannot copy the key. The signing service
   logs every signature. Key Vault does too, if its diagnostic logs are on. The signing service also
   refuses to sign old checkpoints again, and refuses a hand-over to another key unless it was started with
   `--allow-handover`. Key Vault signs whatever the agent's identity sends, so there a
   rewritten history shows only against a copy kept elsewhere: a head file or the vault. There, and
   with that flag on, they can also hand the chain over to a key of their own, and `verify` lists
   every hand-over. To get the service's rules with a key in Key Vault, run the service with
   `--azure-key` and give the agent's identity no permission on the key. That setup has only met a
   stand-in for Key Vault, not the real service. See `docs/signing.md`.
3. **A new chain with a made-up past.** Someone can start a fresh file and fill it with
   invented history. The signing service's log shows when each chain was first signed, the vault
   reports every new chain, and timestamps show the "past" was only signed today.
4. **The file alone cannot prove it is complete.** Records after the last checkpoint are covered
   only by the hash chain, and a file cut back to a checkpoint verifies on its own. Keep a head
   elsewhere, use the vault, or run `verify --witness` against the signing service's record of the
   chain. Someone with write access can also rewrite those records and redo
   the hashes, and a recorder that then carries on from the file signs over them. The recorder
   cannot tell, so it records which records it took over unsigned and `verify` warns
   `signed_after_restart`. An ordinary crash causes the same warning. If every record after the
   last checkpoint is removed and a recorder restarts, `verify` warns `resumed_without_clean_close`,
   because a recorder that stops normally signs a closing mark. A crash right after a checkpoint
   warns too, and a cut back to a point right after an earlier clean close does not. With
   `--witness` these are INVALID as far as the witness reached. Direct use of Key Vault has no witness.
   A holder of the service's token can send false heads, which can make an honest file INVALID or match a rewrite made before the real
   send, and a long flood thins older entries, which `verify` warns about.
   Frequent checkpoints keep that window short.
   Opening an existing file is not fail-open. A recorder refuses to carry on from a file whose chain or
   signatures do not verify, whether or not `strict` is set, because carrying on would sign over it, so write
   access to the file is enough to stop a restart. Timestamp tokens and key pinning are checked only by
   `mnestiq verify`. Keep the file as evidence and start a new one, or opt in to `on_damaged="new_file"`, which
   needs a `FileSink`. It moves aside a file this recorder cannot continue: one that does not verify, or that
   holds another key or chain. It then starts a new chain that `verify` flags.
5. **Root on the vault server** can read the signer's key. Customers who copy anchors into their
   own write-once storage are still covered for everything anchored before.
6. **Time between checkpoints** is the machine's own until the next timestamp.
7. **Redaction hides content, not its shape.** In records before format 1.0 a redacted value keeps
   a plain SHA-256 digest, so a short or guessable value (a yes or no, a known email address) can be
   confirmed by hashing guesses. Since 1.0 each value has its own salt, but `system_prompt_hash` stays
   a plain digest that redaction leaves in place, so a guessed system prompt can still be confirmed. Only prompts, documents, model
   answers and tool arguments and results can be redacted: URLs, error messages and approval text
   stay. `verify` says how many fields were redacted, since the detection rules cannot see them.
8. **The last checkpoint's timestamp.** A signature cannot cover its own timestamp token, and nothing
   signs the last checkpoint's `record_hash`. So the token of the final checkpoint can be removed and the
   file still verifies, with no warning. A head kept elsewhere (`--head`) or the vault shows the change.
9. **The dashboard lists files, it does not count them.** Someone with write access can keep a file out
   of a folder's list by renaming it or by putting 200 junk lines in front.
10. **Capture runs inside the agent's Python process,** and code in that process can work against it.
   Native extensions with their own sockets, `uvloop`, and the network traffic of child processes that are
   not Python are not seen. A secret passed as a bare positional argument to a process is not masked, because
   nothing tells it from any other argument. On Python 3.10 and 3.11, a socket call within two frames of the recursion limit can raise `RecursionError` or go unrecorded.
11. **Emptying or replacing a whole file** starts a chain that looks clean, unless a head or the vault says
   otherwise. `--witness` cannot show it, because the log is picked by the chain id in the file. A file with a new
   chain id has no log to differ from, and `verify` only warns `witness_none`.
12. **A record's hash covers its canonical form.** Respelling a number (`5` as `5.0`), changing the key order or
   JSON spacing, or writing a character as an escape (`\u0061`) leaves the hash the same. The bytes of the line
   change and its values do not.

## Detection is not perfect

The findings that flag a hijack in the evidence (MNQ-001 and MNQ-004: an untrusted input that
leads to an outbound action or a sensitive tool call) were measured on AgentDojo prompt-injection
runs. Replaying 577 recorded hijacks, they flagged about 97%. Of 52 real hijacks of a local
model, they caught 50. They also fire on about one in five clean AgentDojo runs. Every one of
those is a task where the user told the agent to act on data from outside ("pay the bill in this
file", "her email is on her website"), which looks the same in the evidence as an injected
instruction. They miss attacks that need no outside destination and use only values
the user gave, such as persuading the user. MNQ-005, added later, flags data leaked through an
image or a link in the model's answer. It is checked against scripted attacks, not yet measured
at scale. MNQ-006 flags company data sent to an address the company has no record of, with or
without an injection. Content that a tool labels trusted (`internal`) is never treated as an injection, so a
tool that returns text a customer can write, such as an order note, should label it
`tool_output`. MNQ-004 does not compare an argument value over 200 characters. An address or host is
traced only when it is written the way a real one is: one fused to other text with no separator, longer
than 254 characters, or with a label over 63 characters is not traced. An edit of the right type, such as
an emptied `context`, cannot be told apart by the rules. Only `mnestiq verify` shows it, so read findings
together with the verdict. Findings are leads for a person to triage, not verdicts.

## Report a problem

Privately, through [SECURITY.md](../SECURITY.md).
