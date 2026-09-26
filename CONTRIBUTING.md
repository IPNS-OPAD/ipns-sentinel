# Contributing

This is an experimental developer preview, not a certified security boundary.
Start with the [integration guide](docs/INTEGRATION.md) and
[data/credential notes](docs/BYOK.md). The offline demo needs no provider account.

## Public development

[IPNS-OPAD/ipns-sentinel](https://github.com/IPNS-OPAD/ipns-sentinel) is the public
development home. Use its issues and pull requests for product work, documentation,
and synthetic evaluations. Contributors do not need a private checkout, an
invitation, or access to a maintainer's model account.

- Read the [architecture](docs/ARCHITECTURE.md) for the execution and data boundaries.
- Pick a [starter task](docs/ROADMAP.md#starter-tasks), or search existing
  [issues](https://github.com/IPNS-OPAD/ipns-sentinel/issues) before proposing work.
- For a larger change, describe the user-visible outcome and acceptance checks in
  an issue first. For a small documentation fix, a pull request is welcome directly.
- Work in a branch or fork and open a pull request against `main`. Explain what
  changed, how it was checked, and what remains untested. Do not weaken a security
  boundary or change evaluation labels just to make checks pass.
- Maintainers review changes and check CI before merging. Public CI uses offline
  fixtures, not contributor or maintainer provider keys. Live checks are separate,
  explicit, operator-approved work, not a prerequisite for a documentation contribution.

Useful design decisions and roadmap changes should be documented here alongside
the code. Private operational records, credentials, customer data and raw provider
logs do not belong in the public history. Report vulnerabilities through
[SECURITY.md](SECURITY.md), not a public issue or pull request.

## Development

Use Python 3.12+ and uv 0.11.17. From a checkout:

```sh
uv sync --frozen --all-extras
uv run sentinel demo --mode observe
uv run sentinel demo --mode enforce
uv run pytest -q --tb=short
uv run --with mypy --with types-PyYAML mypy src/sentinel --ignore-missing-imports
uv run sentinel corpus-lint evals/codex_redteam
```

The regression suite uses fake scoring and local HTTP fixtures, not hosted model
calls. Optional SDK tests skip without their extras. Docker tests require a trusted
Docker daemon and the existing image; opt in with `SENTINEL_TEST_DOCKER=1`.
The scanner integration tests require `SENTINEL_TEST_GITLEAKS` pointing at Gitleaks
8.30.1. They seed unusable random canaries in disposable repositories and verify
both current-file and history detection; they never use your provider keys.

For release scanning, install the checksum-verified scanner for your platform from
the [official release](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1),
then run `uv run python scripts/check_release.py --gitleaks /path/to/gitleaks`.
Use a full clone, not shallow history. A pass is not proof that no secret exists.

## Changes and reports

- Add regression tests through the public boundary you change. Preserve fail-closed
  behavior where configured, invocation joins, provider validation and bounded I/O.
- Use fictional domains, synthetic trajectories and fixture credentials. Never
  submit production traces, customer data, real secrets or private audit keys.
- Record incomplete assessments, benign warnings, false blocks and abstention
  separately. A harness refusal is not evidence that Sentinel prevented an attack.
- Describe the provider/model, Python/OS version and a minimal sanitized reproducer.
  Do not paste raw provider errors, environment dumps, signed evidence or model
  conversations into issues. Follow [SECURITY.md](SECURITY.md) for vulnerabilities.
- Keep changes small and explain behavioral tradeoffs. Run the relevant tests and
  full suite. Avoid unrelated formatting or generated/runtime files in commits.

CI has read-only permissions, no model credentials and no publishing step. Passing
CI does not establish Docker/host isolation, detector accuracy or release approval.
