# Mnestiq

**A flight recorder for AI agents.** Tamper-evident, signed evidence of what an agent saw,
decided and did, built for incident response.

Mnestiq records every model call, tool call, approval and outbound connection an agent
makes, and tags each piece of model input with its origin: the user, a web page, tool output
or another agent. Records are hash-chained and sealed with signed checkpoints. When an
incident occurs, investigators can identify the run, the step and the input that drove it,
and demonstrate that the record has not been altered since.

## Install

```bash
pip install "mnestiq[anthropic]"     # or mnestiq[openai], or plain mnestiq
```

Optional extras:

| Extra | Adds |
|---|---|
| `azure` | Signing with keys held in Azure Key Vault or Managed HSM |
| `timestamps` | RFC 3161 timestamps from public timestamp authorities, and their verification |

## Quick start

```python
import anthropic
from mnestiq import FileSink, Recorder
from mnestiq.egress import instrument_egress
from mnestiq.integrations.anthropic import instrument_anthropic
from mnestiq.keys import load_private_key

recorder = Recorder(FileSink("evidence.jsonl"), agent_id="support-bot",
                    signing_key=load_private_key("keys/signing.key"))
client = instrument_anthropic(anthropic.Anthropic(), recorder)
instrument_egress()

with recorder.run():
    ...  # your agent, unchanged

recorder.close()
```

```bash
mnestiq keygen --out keys
mnestiq verify evidence.jsonl --trusted-key keys/signing.pub
mnestiq dashboard . --trusted-key keys/signing.pub
```

## Production signing

A key file readable by the agent is suitable for evaluation only. In production, keep the
signing key out of the agent's reach, so that a compromised agent cannot copy it or re-sign
earlier evidence:

```python
from mnestiq import AzureKeyVaultSigner, FileSink, Recorder, SignerClient, Timestamper

# Azure Key Vault: the key never leaves the vault; only a SHA-256 digest is sent.
signer = AzureKeyVaultSigner("https://<vault>.vault.azure.net/keys/<name>/<version>")

# Or a local signing service running under a separate account (`mnestiq signer serve`).
signer = SignerClient.from_env()

recorder = Recorder(FileSink("evidence.jsonl"), agent_id="support-bot", signer=signer,
                    timestamper=Timestamper(),       # independent RFC 3161 timestamps
                    checkpoint_interval=300)         # signed heartbeat when idle
```

Keys are rotated with a signed hand-over (`recorder.rotate_signer(new_signer)`), which the
verifier follows. See the [signing guide](https://github.com/mnestiq/mnestiq/blob/main/docs/signing.md).

## Security model

Evidence is tamper-evident after it is written: edits, deletions, reordering, re-signing with
another key and backdating are detected. It cannot prove that a compromised agent told the
truth at the time of writing. The [threat model](https://github.com/mnestiq/mnestiq/blob/main/docs/threat-model.md)
lists each attack considered, how it is detected, and the automated test that demonstrates it.
Independent reviewers are invited to try the
[break-it challenge](https://github.com/mnestiq/mnestiq/blob/main/examples/break-it/README.md).

## Links

- Documentation and examples: https://github.com/mnestiq/mnestiq
- Evidence format specification: https://github.com/mnestiq/mnestiq/blob/main/spec/SPEC.md
- Changelog: https://github.com/mnestiq/mnestiq/blob/main/CHANGELOG.md
- Security policy and vulnerability reporting: https://github.com/mnestiq/mnestiq/blob/main/SECURITY.md

Licensed under Apache-2.0.
