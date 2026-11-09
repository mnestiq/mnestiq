# Signing keys: keep the key away from the agent

Checkpoints are signed so that nobody can change the records they cover without it
showing. That only holds while the signing key is safe. If the key sits in a file the
agent can read, someone who takes over the agent can copy it and later rewrite history and
sign it again.

So in production the key lives somewhere the agent cannot read it. The agent only asks for
signatures. There are four ways to do this:

| | Where the key is | Good for |
|---|---|---|
| `LocalSigner` / `signing_key=` | A file the agent reads | Trying things out, tests |
| `SignerClient` + `mnestiq signer serve` | A signing service under another account on the same machine | Any machine, no cloud needed |
| `AzureKeyVaultSigner` | Azure Key Vault or Managed HSM. It signs whatever the agent's identity sends | Azure customers |
| `SignerClient` + `mnestiq signer serve --azure-key` | Azure Key Vault or Managed HSM, behind the signing service's rules. The agent's identity has no permission on the key | Azure customers who want those rules. The Key Vault signer was tested on real Azure on 2026-10-07. The service in front of it has only met a stand-in |

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
  each chain only forward. Each checkpoint must cover the records just before it. If a signed
  checkpoint is lost before it reaches the file, the next one may cover the same records again
  and more, and the service signs it only once the record hashes show the records it signed are
  unchanged. The last checkpoint sent again, after an answer was lost, is signed only if the request
  is byte-identical.
- **Not protected:** while someone controls the agent, they can feed it false events, and
  those get signed like true ones. Evidence is tamper-evident after it is written, not
  truthful at the source. For this reason, the Workbench compares the agent's account with
  records the agent does not control.
- They could start a new chain and fill it with a made-up past. The signing service's log
  shows when each chain was first signed, and the Evidence Vault reports every new chain,
  so a "past" that only appeared today stands out.
- The signing service logs every signature. Key Vault does too, if its diagnostic logs are on.
  Compare the log with the evidence: a signature in the log that is missing from the evidence can mean
  someone asked for one and hid the result, or that a checkpoint was lost in a crash.

## The signing service

`mnestiq signer serve` holds the key and signs for agents that have its token. Run it under
its own operating-system account so the agent's account cannot read the key.

It only signs:

- checkpoint records for its own key, nothing else;
- with a timestamp within 5 minutes of its own clock (`--max-skew`);
- per chain, only the checkpoint that starts right after the last one it signed.

It refuses a checkpoint that names a `next_key` unless it was started with
`mnestiq signer serve --allow-handover`. A pinned key trusts what it hands over to, so with this on,
anyone holding the token could name a key of their own and sign the rest of the chain. Leave it off,
and turn it on only to change keys.

Every signature is appended to `signatures.jsonl` in its folder. A byte-identical repeat gets the
signature already given, and its line is marked `"repeat": true`. If the log cannot be written after
a checkpoint is signed, the service says so and the identical request sent again completes the log.

One folder serves one running service. A second one on the same folder refuses to start.

`--max-chains` limits how many chains the service keeps, 10,000 by default. A new chain past the limit is
refused, and chains already held keep working. Signing and the witness have a limit each, so heads alone cannot
use up signing's. Anyone holding the token can fill the limit by naming new chains. Treat a refusal you did not
expect as an incident.

A checkpoint covers at most 2^40 records, far more than a recorder can hold. If a chain stops being
signed with "only the next checkpoint is signed" and you did not expect it, someone holding the
token may have had a checkpoint signed that does not match the records. Treat it as an incident:
compare `signatures.jsonl` with the evidence. To go on recording, start a new evidence file, which
is a new chain, and keep the old file and the log as they are. Do not edit `state.json` to get
past the refusal, since that is the record that stops history from being signed again.

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

## The witness

Records after the last checkpoint have only the hash chain. The signing service can hold a second
copy of where each chain has got to. A recorder using `SignerClient` sends its latest record hash
to the service in the background, and the service adds every checkpoint it signs. Sending does not
slow recording. `close()` waits up to 2 seconds for the last send. An older service is simply not asked.

```
mnestiq verify evidence.jsonl --trusted-key key.pub --witness /var/lib/mnestiq-signer
```

A record that differs from what the witness saw, or a file that ends before it, is INVALID. Run this
with a folder the agent's account cannot write to.

What it does not do:

- Records written after the last send were not witnessed, and `verify` says how far it reached.
- Using `AzureKeyVaultSigner` directly, without the service, has no witness.
- It cannot show that a whole file was replaced. The log is picked by the chain id in the file, so a file with a
  new chain id has no log to differ from, and `verify` only warns `witness_none`.
- A holder of the service's token can send false heads. That can make an honest file INVALID, or
  match a rewrite made before the real send. A flood lasting minutes thins older entries, which
  `verify` warns as `witness_thinned`. Checkpoints the service signed are kept apart from that.

To make the unwitnessed window as small as you want, `Recorder(checkpoint_on=("tool_call", "egress"))`
signs right after those events, at the cost of one signature each.

## Azure Key Vault

The key is created in Key Vault and held there. The recorder sends only the
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

## Key Vault behind the signing service

Key Vault used directly sees only a digest, so it signs whatever the agent's identity sends,
a hand-over to another key or a rewritten history included. To keep the key in Key Vault and
still have the signing service's rules, put the service in front of the vault. The agent
holds only the service's token.

**The agent's identity must have no sign permission on the key.** If it can still sign, someone
in control of the agent can call Key Vault directly, and the service protects nothing. Only the
service's identity gets the role from the section above:

```bash
az role assignment create --assignee <service identity object id> --role "Mnestiq recorder signer" \
  --scope "$(az keyvault show --name <vault> --query id -o tsv)/keys/mnestiq-recorder"
az role assignment list --assignee <agent identity object id> --all -o table
```

The second command is the check: nothing it lists may allow `keys/sign/action` on this key,
including roles that apply to the whole vault, its resource group or its subscription.

Then, as the service's own account:

```bash
pip install "mnestiq[azure]"
mnestiq signer init /var/lib/mnestiq-signer --no-key
mnestiq signer serve /var/lib/mnestiq-signer --azure-key https://<vault>.vault.azure.net/keys/mnestiq-recorder/<version>
```

`signer init --no-key` makes only the token the agent needs. With no local key in the folder, the
service cannot start on the wrong key if `--azure-key` is ever left out.

The service prints the vault key's public half when it starts. Pin that one with
`mnestiq verify --trusted-key`. The agent's side is the same as for any signing service
(`SignerClient.from_env()`, see above).

All the service's rules apply as they do with a local key: the clock check, the forward-only
order per chain, byte-identical repeats, the refusal of a hand-over unless it was started with
`--allow-handover`, and the log in `signatures.jsonl`. A refused request never reaches the
vault. If the vault fails, or answers with a signature that does not match the key, the agent gets
an error, nothing is logged, nothing moves, and the same request can be sent again.

A slow vault holds up only the chain it is signing for. The service makes one try per request and
does not wait out a throttling answer from Key Vault, and it answers every request within 8 seconds,
so a vault that is throttling or down shows up as an error and the recorder tries again later. A call
it stopped waiting for may still finish at the vault, so the vault's log can show a signature the
service never used. The time Azure's sign-in takes is limited where the credential allows it, and
the 8 seconds apply to the service's answer whatever the credential does.

The service signs in to Azure through `DefaultAzureCredential`, as above. Mnestiq never takes,
prints or stores an Azure secret.

**Use a service principal, with a certificate only the service's account can read.** Set
`AZURE_TENANT_ID`, `AZURE_CLIENT_ID` and `AZURE_CLIENT_CERTIFICATE_PATH` in the service's
environment, not the agent's. Azure's library needs an RSA key in that certificate.

**A managed identity on a host the agent also runs on is not supported for this setup.** Any
process there can ask the platform for that identity's token, whichever account it runs under, so
the agent could sign as the service. The service only listens on its own machine, so a managed
identity would have to belong to a host the agent cannot reach, which this setup does not offer.

With a service principal, the vault's own log gives a check: a `KeySign` by any identity other than
that service principal is a request that went around the service. This check says nothing about who
was really behind a call made with the service's own identity.

### The check on the agent's identity

```bash
az role assignment list --assignee <agent identity object id> --include-inherited --include-groups \
  --scope "$(az keyvault show --name <vault> --query id -o tsv)/keys/mnestiq-recorder" -o table
```

Treat this as a first look, not a proof. Anything it lists that allows
`Microsoft.KeyVault/vaults/keys/sign/action` has to go: Key Vault Administrator, Key Vault Crypto
Officer, Key Vault Crypto User, or a custom role with that action or a wildcard over it. It may not
show every path to the permission, such as membership of nested groups. It shows nothing about vault
access policies, so the vault must use Azure RBAC (`--enable-rbac-authorization true`, as above).
The check that settles it is to sign in as the agent's identity and ask Key Vault to sign a test
digest with this key. It must be refused.

### The token

The token is the agent's only way in, and anyone holding it can ask for signatures. The service
refuses to start if `signer.token` holds fewer than 32 characters, and it reads the file once, at
start-up. To change it, or to shut out a token that has leaked:

1. Stop the service, so nothing is signed with the old token.
2. As the service's account, replace the contents of `signer.token` with a new value, such as the
   output of `python -c "print(__import__('secrets').token_hex(32))"`.
3. Start the service and give the new value to the agent as `MNESTIQ_SIGNER_TOKEN`.

Compare `signatures.jsonl` with the evidence for the time the old token was exposed.

### Moving a folder to another key

A folder belongs to one key. The service refuses to start on a folder whose chains were signed by
a different key, because those chains cannot go on under another key without a signed hand-over.
Use a new folder for Key Vault and keep the old one. To carry a running chain across, hand it over
first with `recorder.rotate_signer(new_signer)` while the old service runs with `--allow-handover`,
then continue against the new service.

This setup has been tested against a stand-in for Key Vault and not yet against the real service.

## Proving when: timestamps

A checkpoint carries the time from the agent's machine, and whoever controls that machine
controls its clock. An RFC 3161 timestamp adds a time from outside: a timestamp authority
signs "this checkpoint's signature existed at T" with a certificate from a public
certificate authority. Only the SHA-256 of the signature is sent.

```bash
pip install "mnestiq[timestamps]"
```

```python
from mnestiq import Recorder, Timestamper

recorder = Recorder(sink, agent_id="support-bot", signer=signer, timestamper=Timestamper())
```

`Timestamper()` asks DigiCert, then Sectigo. Each token is checked before it is written, so
a bad answer moves on to the next authority. If none answers, the checkpoint is still
signed and written, without a token, and a warning is logged. Each checkpoint waits for
the authority (10 seconds at most per authority, `timeout=`), so use it with checkpoints
every 100 records or more, not every record.

`mnestiq verify` checks every token: that it covers this checkpoint's signature, the
authority's signature, and its certificate chain up to DigiCert Trusted Root G4 or USERTrust
RSA (Sectigo). Use `--tsa-root roots.pem` to trust other authorities instead. It reports the
proven time, and warns if the agent's clock disagrees with it.

## Changing keys

A chain is signed by one key at a time. To move to a new key, hand the chain over:

```python
recorder.rotate_signer(new_signer)
```

This writes a note and a checkpoint signed by the old key that names the new one
(`next_key`). From there on the verifier expects the new key. If you pinned the old key,
the new one is trusted for this chain because the old key vouched for it. A key change
without a hand-over is an error, pinned or not.

A signing service signs a hand-over only if it was started with `--allow-handover`. Key Vault signs
whatever the agent's identity sends, so there, and while that flag is on, someone in control of the
agent can hand the chain over to a key of their own. `mnestiq verify` lists every hand-over.

A recorder that opens an existing evidence file with a different key refuses to start, so
a configuration change cannot quietly produce a file that fails verification.
