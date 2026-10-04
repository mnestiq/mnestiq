# Mnestiq

**A flight recorder for AI agents.** Tamper-evident, signed evidence of what an agent saw,
decided and did, built for incident response.

Mnestiq records every model call, tool call, approval and outbound connection your agent
makes, tags every piece of model input with where it came from (user, web page, tool
output, another agent), and seals the record with a hash chain and signed checkpoints.
When something goes wrong you can name the run, the step and the input that drove it, and
prove the record was not edited afterwards.

## Install

```bash
pip install "mnestiq[anthropic]"     # or mnestiq[openai], or plain mnestiq
```

## Use

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

## Links

- Documentation and examples: https://github.com/mnestiq/mnestiq
- Evidence format specification: https://github.com/mnestiq/mnestiq/blob/main/spec/SPEC.md
- Security policy: https://github.com/mnestiq/mnestiq/blob/main/SECURITY.md

Apache-2.0.
