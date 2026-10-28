# Installing the recorder

The recorder is a Python package. It needs Python 3.10 or newer and runs on Windows, macOS and Linux.
It makes no network calls of its own: evidence stays where you write it.

## 1. Install

**Windows** (PowerShell):

```powershell
py -m venv mnestiq-env
mnestiq-env\Scripts\activate
pip install mnestiq
```

If `py` is not found, install Python from python.org and tick "Add python.exe to PATH".

**macOS** (Terminal):

```bash
python3 -m venv mnestiq-env
source mnestiq-env/bin/activate
pip install mnestiq
```

If `python3` is not found, install it with `xcode-select --install` or from python.org.

**Linux** (Debian or Ubuntu):

```bash
sudo apt install python3-venv
python3 -m venv mnestiq-env
source mnestiq-env/bin/activate
pip install mnestiq
```

Add what your agent uses: `pip install "mnestiq[anthropic]"`, `"mnestiq[openai]"`, `"mnestiq[azure]"`
(signing with Azure Key Vault) or `"mnestiq[timestamps]"` (RFC 3161 timestamps). They combine:
`"mnestiq[openai,azure]"`.

## 2. Check it works

```bash
mnestiq demo
```

It records a scripted incident in `./mnestiq-demo`, walks through the investigation and opens the
dashboard in your browser. Ctrl+C stops the dashboard. Nothing leaves your machine.

## 3. Make a signing key

```bash
mnestiq keygen --out keys
```

`keys/signing.key` signs the evidence: give it to the recorder only. `keys/signing.pub` is the public
key you verify against. For trying it out, a key file is fine. In production, keep the key where the
agent can't read it, in a signing service under another account or in Azure Key Vault:
see [signing.md](signing.md).

## 4. Record your agent

Either run the proxy and point the agent at it (no code changes, any language), or add the recorder to
your Python code. Both are in the [README](../README.md#record-your-own-agent). Then:

```bash
mnestiq verify evidence.jsonl --trusted-key keys/signing.pub
mnestiq dashboard evidence.jsonl --trusted-key keys/signing.pub
```

## Where evidence is kept

Wherever you point it: `FileSink("evidence.jsonl")` or the proxy's first argument. On Linux and macOS
new evidence files are readable by their owner only. On Windows a file takes its folder's permissions,
so keep evidence in a folder only the agent's account can read. Evidence holds what the agent read and
wrote, which may include personal data or secrets that passed through it: treat it like the data it
came from. `mnestiq redact` makes a copy without that content that still verifies.

## Uninstall

`pip uninstall mnestiq`, then delete the environment folder. Evidence files and keys are yours: delete
them separately when you no longer need them.
