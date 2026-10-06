# Break it

`evidence.jsonl` is the record of a prompt-injection incident: a support agent reads a web
page with a hidden instruction, and emails the customer export to an outside address after an
automatic policy approves it. It is hash-chained, signed, and each checkpoint carries an RFC
3161 timestamp from DigiCert. The signing key was thrown away when the file was made.

**The challenge:** change `evidence.jsonl` so that this still says `VALID`:

```bash
pip install "mnestiq[timestamps]"
mnestiq verify evidence.jsonl --trusted-key recorder.pub --head head.json
```

For example: make a person approve the email instead of the policy, remove the email,
change where it went, make the web page innocent, move the incident to another day, or
remove the end of the file.

`recorder.pub` and `head.json` stand for what the investigator holds apart from the
evidence: the recorder's public key, and the latest checkpoint kept somewhere else (or by
the Evidence Vault). They are not yours to change. Check you have the originals:

```
sha256 recorder.pub  895087d94e3c8926b7eb62620c747e3c4ceed4af20e8c7812c88e0b38cbdae67
sha256 head.json     8c835bf5a9f46385b1e25890eba145e0c6e2c9b4ebd2b91a257ee497574e121a
```

Before you start, the limits we already state, so you don't spend time on them:

- Without `--head`, a file cut back to an earlier checkpoint verifies. With it, it does not.
- Whoever controls the agent while it runs can make it record false events. The evidence
  proves what was written and when, not that it was true. See
  [docs/threat-model.md](../../docs/threat-model.md).

If you find a way, please report it privately: [SECURITY.md](../../SECURITY.md).

`python examples/break_it.py` makes a fresh kit (with a new key, so new hashes).
