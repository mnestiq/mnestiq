# Threat model

What Mnestiq evidence protects, against whom, what it catches, and what it does not do.
Every claim below has a test that carries out the attack: `python/tests/test_attacks.py`
(run `pytest tests/test_attacks.py -v`), and you can try your own on the
[break-it kit](../examples/break-it/README.md).

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
| Stop the recorder | Heartbeats: a gap in the file is reported, and the vault alerts while it happens | `test_d1` |

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
   Mnestiq Workbench checks the agent's story against network, proxy, DNS and cloud logs the
   agent does not control, and flags traffic no recorded step explains.
2. **Signatures while in control.** Someone in control of the agent can ask the signing service
   or Key Vault for signatures on new checkpoints. They cannot take the key away, and every
   signature is logged by the service or by Key Vault. The signing service also refuses to sign
   old checkpoints again. Key Vault signs whatever the agent's identity sends, so there a
   rewritten history shows only against a copy kept elsewhere: a head file or the vault.
3. **A new chain with a made-up past.** Someone can start a fresh file and fill it with
   invented history. The signing service's log shows when each chain was first signed, the vault
   reports every new chain, and timestamps show the "past" was only signed today.
4. **The file alone cannot prove it is complete.** Records after the last checkpoint are covered
   only by the hash chain, and a file cut back to a checkpoint verifies on its own. Keep a head
   elsewhere, or use the vault.
5. **Root on the vault server** can read the signer's key. Customers who copy anchors into their
   own write-once storage are still covered for everything anchored before.
6. **Time between checkpoints** is the machine's own until the next timestamp.
7. **Redaction hides content, not its shape.** A redacted value keeps its SHA-256 digest, so a
   short or guessable value (a yes or no, a known email address) can be confirmed by hashing
   guesses. Only prompts, documents and tool arguments and results can be redacted: URLs, error
   messages and approval text stay. `verify` says how many fields were redacted, since the
   detection rules cannot see them.

## Detection is not perfect

The findings that flag a hijack in the evidence (MNQ-001 and MNQ-004: an untrusted input that
leads to an outbound action or a sensitive tool call) were measured on AgentDojo prompt-injection
runs. Replaying 577 recorded hijacks, they flagged about 97%. Of 52 real hijacks of a local
model, they caught 50. They also fire on about one in five clean runs,
where an agent legitimately acts on data that came from outside, such as an email address in
a customer's message. They miss attacks that need no outside destination and use only values
the user gave, such as persuading the user. MNQ-005, added later, flags data leaked through an
image or a link in the model's answer. It is checked against scripted attacks, not yet measured
at scale. Content that a tool labels trusted (`internal`) is never treated as an injection, so a
tool that returns text a customer can write, such as an order note, should label it
`tool_output`. Findings are leads for a person to triage, not verdicts.

## Report a problem

Privately, through [SECURITY.md](../SECURITY.md).
