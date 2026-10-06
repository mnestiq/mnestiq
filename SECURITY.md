# Security policy

## Reporting a vulnerability

Please do not open a public issue for security problems.

Report privately through GitHub:
[Report a vulnerability](https://github.com/mnestiq/mnestiq/security/advisories/new).

Include what you found, how to reproduce it, and the version affected. You will get an
acknowledgement within a few days, and we will agree on a disclosure date once a fix is
ready.

## Scope

In scope: the recorder, verifier, CLI and dashboard in this repository, and the evidence
format defined in `spec/`. Of particular interest:

- ways to alter, delete or reorder evidence records without `mnestiq verify` reporting it
- ways to forge a checkpoint that passes verification with a pinned key
- the dashboard or reports executing or fetching attacker-controlled content
- the recorder breaking or blocking the agent it is recording

The known limits listed in [docs/threat-model.md](docs/threat-model.md) and `spec/SPEC.md`
(sections 2 and 6.5) are documented behaviour, not vulnerabilities. The
[break-it kit](examples/break-it/README.md) is a good place to start.

## Supported versions

Mnestiq is pre-1.0. Fixes are made on the latest release only.
