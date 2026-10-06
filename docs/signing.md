# Signing keys: keep the key away from the agent

Checkpoints are signed so that nobody can change evidence after it was written without
it showing. That only holds while the signing key is safe. If the key sits in a file the
agent can read, someone who takes over the agent can copy it and later rewrite history and
sign it again.

So in production the key lives somewhere the agent cannot read it. The agent only asks for
signatures. There are three ways to do this:

| | Where the key is | Good for |
|---|---|---|
| `LocalSigner` / `signing_key=` | A file the agent reads | Trying things out, tests |
| `SignerClient` + `mnestiq signer serve` | A signing service under another account on the same machine | Any machine, no cloud needed |
| `AzureKeyVaultSigner` | Azure Key Vault or Managed HSM, never leaves it | Azure customers |

The recorder asks for one signature per checkpoint (by default every 100 records, and at
close), not per event. A remote signer adds one round trip per checkpoint. If the signer
is down, the agent carries on: records are written, the failure is counted in
`recorder.failures`, and signing is tried again after `retry_after` seconds (30 by default),
covering everything since the last checkpoint.

Every signature the recorder gets back is checked against the signer's public key before it
goes into the evidence.

## What this protects, and what it doesn't

- **Protected:** someone who takes over the agent, or later gets at the evidence, cannot copy
  the key and re-sign a rewritten history. With the signing service they also cannot get
  earlier checkpoints signed again, even while they control the agent: the service signs
  each chain only forward.
- **Not protected:** while someone controls the agent, they can feed it false events, and
  those get signed like true ones. Evidence is tamper-evident after it is written, not
  truthful at the source. The Workbench cross-checks the agent's story against network and
  proxy logs for this reason.
- They could start a new chain and fill it with a made-up past. The signing service's log
  shows when each chain was first signed, and the Evidence Vault reports every new chain,
  so a "past" that only appeared today stands out.
- Both the signing service and Key Vault keep their own log of every signature. Compare it
  with the evidence: a signature in the log that is missing from the evidence means someone
  asked for one and hid the result.

## The signing service

`mnestiq signer serve` holds the key and signs for agents that have its token. Run it under
its own operating-system account so the agent's account cannot read the key.

It only signs:

- checkpoint records for its own key, nothing else;
- with a timestamp within 5 minutes of its own clock (`--max-skew`);
- per chain, only the checkpoint that starts right after the last one it signed.

Every signature is appended to `signatures.jsonl` in its folder.

### Linux

```bash
sudo useradd --system --home-dir /var/lib/mnestiq-signer --create-home mnestiq-signer
sudo chmod 700 /var/lib/mnestiq-signer
sudo -u mnestiq-signer mnestiq signer init /var/lib/mnestiq-signer --alg ed25519
```

A systemd unit, `/etc/systemd/system/mnestiq-signer.service`:

```ini
[Unit]
Description=Mnestiq checkpoint signer

[Service]
User=mnestiq-signer
ExecStart=/usr/local/bin/mnestiq signer serve /var/lib/mnestiq-signer --listen 127.0.0.1:8741
Restart=on-failure
ProtectSystem=strict
ReadWritePaths=/var/lib/mnestiq-signer
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

### Windows

As an administrator in PowerShell, create the account and a folder only it can open:

```powershell
$cred = Get-Credential -UserName mnestiq-signer -Message "Password for the signer account"
New-LocalUser -Name mnestiq-signer -Password $cred.Password -PasswordNeverExpires
New-Item -ItemType Directory C:\ProgramData\mnestiq-signer
icacls C:\ProgramData\mnestiq-signer /inheritance:r /grant:r "mnestiq-signer:(OI)(CI)F" "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F"
```

Create the key as that account, then start the service at boot under it:

```powershell
runas /user:mnestiq-signer "mnestiq signer init C:\ProgramData\mnestiq-signer"
$action = New-ScheduledTaskAction -Execute "mnestiq.exe" -Argument "signer serve C:\ProgramData\mnestiq-signer"
$trigger = New-ScheduledTaskTrigger -AtStartup
Register-ScheduledTask -TaskName "Mnestiq signer" -Action $action -Trigger $trigger -User mnestiq-signer -Password $cred.GetNetworkCredential().Password
```

### The agent's side

Give the agent the token, not the key. The token is in `signer.token`. Put it in the
agent's environment as `MNESTIQ_SIGNER_TOKEN`:

```python
from mnestiq import FileSink, Recorder, SignerClient

signer = SignerClient.from_env()          # MNESTIQ_SIGNER (default 127.0.0.1:8741) and MNESTIQ_SIGNER_TOKEN
recorder = Recorder(FileSink("evidence.jsonl"), agent_id="support-bot", signer=signer)
```

The token never crosses the connection: client and service prove they both hold it with a
challenge and response. The service listens on this machine only.

Pin the public key that `signer init` printed when you verify:

```bash
mnestiq verify evidence.jsonl --trusted-key <public key>
```

## Azure Key Vault

The key is created in Key Vault and cannot be exported. The recorder sends only the
SHA-256 of each checkpoint and gets the signature back. Key Vault has no Ed25519, so the
key is P-256 (`ecdsa-p256-sha256` in the evidence).

```bash
pip install "mnestiq[azure]"
```

Create a vault in an EU region and a key (Premium vaults can use `--kty EC-HSM` to keep the
key in a hardware module):

```bash
az keyvault create --name <vault> --resource-group <rg> --location westeurope --enable-rbac-authorization true
az keyvault key create --vault-name <vault> --name mnestiq-recorder --kty EC --curve P-256 --ops sign verify
az keyvault key show --vault-name <vault> --name mnestiq-recorder --query key.kid -o tsv
```

The last command prints the key's URL with its version. Use that full URL: if Key Vault
rotated the key underneath, the evidence would change key without a signed hand-over, and
the verifier would report it.

Give the agent's identity (a managed identity, or an app registration) the two permissions
it needs and nothing else. Save this as `signer-role.json`:

```json
{
  "Name": "Mnestiq recorder signer",
  "Description": "Read a key's public half and sign with it.",
  "Actions": [],
  "DataActions": [
    "Microsoft.KeyVault/vaults/keys/read",
    "Microsoft.KeyVault/vaults/keys/sign/action"
  ],
  "AssignableScopes": ["/subscriptions/<subscription id>"]
}
```

```bash
az role definition create --role-definition @signer-role.json
az role assignment create --assignee <agent identity object id> --role "Mnestiq recorder signer" \
  --scope "$(az keyvault show --name <vault> --query id -o tsv)/keys/mnestiq-recorder"
```

In the agent:

```python
from mnestiq import AzureKeyVaultSigner, FileSink, Recorder

signer = AzureKeyVaultSigner("https://<vault>.vault.azure.net/keys/mnestiq-recorder/<version>")
recorder = Recorder(FileSink("evidence.jsonl"), agent_id="support-bot", signer=signer)
print(signer.public_key)   # pin this with mnestiq verify --trusted-key
```

Credentials come from `DefaultAzureCredential`: a managed identity on Azure, environment
variables, or the Azure CLI login.

### Key Vault's own record of every signature

Send the vault's audit log to your Log Analytics (Sentinel) workspace:

```bash
az monitor diagnostic-settings create --name mnestiq-audit \
  --resource "$(az keyvault show --name <vault> --query id -o tsv)" \
  --workspace <workspace resource id> --logs '[{"category":"AuditEvent","enabled":true}]'
```

```kusto
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.KEYVAULT" and OperationName == "KeySign"
| project TimeGenerated, CallerIPAddress, identity_claim_oid_g, id_s, ResultSignature
```

This is a second record, kept by Microsoft rather than by you or us, of when each signature
was made and by which identity.

## Changing keys

A chain is signed by one key at a time. To move to a new key, hand the chain over:

```python
recorder.rotate_signer(new_signer)
```

This writes a note and a checkpoint signed by the old key that names the new one
(`next_key`). From there on the verifier expects the new key. If you pinned the old key,
the new one is trusted for this chain because the old key vouched for it. A key change
without a hand-over is an error, pinned or not.

A recorder that opens an existing evidence file with a different key refuses to start, so
a configuration change cannot quietly produce a file that fails verification.
