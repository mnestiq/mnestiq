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

## Check a release

Releases are built by GitHub Actions from a tagged commit and published to PyPI with Trusted
Publishing: no person holds a PyPI token, and a maintainer approves each publish.

- **On PyPI**, each file shows its publish attestation: who published it, from which
  repository and workflow.
- **Build provenance:** download the wheel or source archive and run
  `gh attestation verify mnestiq-<version>-py3-none-any.whl --repo mnestiq/mnestiq
  --signer-workflow mnestiq/mnestiq/.github/workflows/release.yml --source-ref refs/tags/v<version>`.
  It checks the file was built by this repository's release workflow, from the release's tag.
  Without the last two options it checks only that some workflow in this repository built it.
- Every action in the workflows is pinned to a commit, and Dependabot proposes updates.
  CI checks dependencies for known vulnerabilities (`pip-audit`).

## Supported versions

Mnestiq is pre-1.0. Fixes are made on the latest release only.
