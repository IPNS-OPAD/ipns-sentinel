# Public roadmap and starter tasks

IPNS Sentinel is an experimental developer preview. This is an ordering of work
we would like to evaluate with contributors, not a delivery schedule, security
certification or promise of support for an unreleased feature.

The [public repository](https://github.com/IPNS-OPAD/ipns-sentinel) is the home for
product development. Proposals, reviewed implementation changes, useful design
decisions and sanitized results belong here. Private operational records, customer
data, credentials and raw provider logs do not. The project remains Apache-2.0;
using or contributing to it does not require private repository access.

## Available today

- Key-free offline demo with fixture scoring, not a live detector benchmark.
- Python `guard` / `aguard` wrappers, assessment-only APIs and a Claude Code hook.
- Jev/Claude monitor backends, typed verdicts, deterministic rules, fleet
  correlation, audit records and configurable alerts.
- A 12-case synthetic pilot with explicit self-hosted scoring and a larger
  development corpus. These runners do not execute the recorded tool proposals.
- An experimental restricted Python broker. It is not a general-purpose sandbox
  for every agent tool or an automatic fleet kill switch.

Read the [architecture and boundaries](ARCHITECTURE.md) and
[integration guide](INTEGRATION.md) before relying on any of these paths.

## Starter tasks

These three tasks are independent; none is blocked by another starter task.
They are proposals, not delivered features or assignments. Search
[open issues](https://github.com/IPNS-OPAD/ipns-sentinel/issues) and discuss the
scope before starting so work is not duplicated. An offline implementation and
synthetic regression checks should be enough for each; no paid model is required.

### 1. Runnable asynchronous integration example

**Outcome:** a developer can run a small async executor through `aguard`, see an
allowed call return its value and a denied call avoid execution, then adapt it
to their own application. This complements the guide's application-hook sketch.

Acceptance checks:

- Run from a documented clean install without provider accounts or network calls.
- Use explicit fake scoring, synthetic inputs and temporary audit state; ignore
  ambient provider credentials and configuration. Clearly label the example as
  control-flow verification, not detection quality.
- Show `ToolBlocked` handling without retrying through the original executor.
- Verify allowed output, zero denied executor calls, and invocation-joined receipts
  for success and a synthetic executor failure or cancellation.
- Add an automated offline regression and link the example from the integration guide.

### 2. Offline pilot-report summary

**Outcome:** a tester can inspect an existing pilot `report.json` without making
a model call or rerunning an evaluation, and see what to investigate next.

Acceptance checks:

- Read an explicitly supplied report; never discover credentials, endpoints or
  runtime directories. Do not modify the input report or send it anywhere.
- Support current format-2 reports and clearly label unavailable format-1 fields;
  reject unsupported or malformed formats with a useful, sanitized error.
- Show completed-case denominators, attack misses, semantic false alerts,
  operational holds, incomplete assessments and premature blocks separately.
- Summarize available latency measurements with sample counts. Do not convert
  missing values into zeros or treat repeated cases as independent coverage.
- Output an allowlisted summary, not arbitrary report fields, raw responses,
  secrets or endpoint addresses; test redaction with synthetic canaries.
- Include synthetic complete, incomplete and older-format fixtures plus a short
  usage example in the pilot guide. Do not change scoring or pass/fail semantics.

### 3. Additional matched coordination evaluations

**Outcome:** developers can examine a new coordination scenario alongside
authorized and independent-agent controls, rather than improving attack recall
without measuring false positives.

Acceptance checks:

- Add at least one new covert/sanctioned matched pair and an independent-worker
  control, keeping benign coverage at least as large as attack coverage.
- Use 3-6 agents per fleet case, one run identity per case, distinct agent IDs,
  chronological steps, meaningful peer context and a span within 900 seconds.
- Put the sanctioned channel explicitly in operator-declared policy. Record the
  first violating event; blocks before it are not successful timely detection.
- Use fresh correlation state for each case, synthetic names/data and inert
  proposals. Never execute the proposals or target a real external system.
- Pass corpus validation and add regression checks for case structure, isolation,
  annotations and expected controls. Record fake-scoring results as plumbing
  diagnostics, not evidence of detector quality; do not tune to the fixture labels.
- Describe how the scenario differs from the existing fleet cases. Any live model
  run requires separate endpoint, capacity and data-handling approval.

## Next: evidence and integration reliability

- **Run-scoped correlation:** define and test isolation across unrelated runs and
  trust domains, including persisted state and repeated agent IDs. Today, callers
  must separate observer/correlator instances and persistence paths; `run_id`
  alone is not a correlation namespace. This needs an explicit design and migration
  review before changing shared storage semantics.
- **False-positive diagnosis:** use matched sanctioned/independent controls and
  per-question evidence before changing thresholds or prompts. Publish denominators,
  failures and configuration alongside sanitized results.
- **Latency and serving compatibility:** measure complete request latency, including
  failures, across explicitly identified deployments. Separate serving overhead,
  model behavior and monitor pipeline cost; a provider's speed claim is not an
  end-to-end Sentinel measurement.
- **Held-out evaluation:** separate new evaluation material from development and
  tuning cases; expand threat-class coverage while retaining adequate benign
  controls. Distinguish recorded replay from bounded live-harness prevention tests.

The early tester result documented in the [README](../README.md#early-feedback-not-a-benchmark)
is a diagnostic example, not a target score or a model leaderboard.

## Later: broader execution and platform coverage

- New productive tool adapters need explicit authorization, effect/receipt
  collection, replay handling and host isolation review before enforcement claims.
- Native Windows support remains open in [issue #1](https://github.com/IPNS-OPAD/ipns-sentinel/issues/1).
  Current Windows users should use WSL. Fixing an import alone does not establish
  correct cross-platform audit locking; contention and process-failure tests matter.
- Convenient package distribution should follow reproducible installation and
  [release checks](RELEASE-CHECKLIST.md). Installation from the repository is the
  documented path today; this roadmap does not announce a package-registry release.

## How to contribute

Follow [CONTRIBUTING](../CONTRIBUTING.md), open an issue for a larger proposal,
and submit a focused pull request against public `main`. State what works, what
does not and how to reproduce the result. Maintainers review the change and CI
before merging. A CI pass alone does not certify model accuracy or containment.

Keep vulnerabilities in the [private reporting channel](../SECURITY.md). Do not
attach keys, private endpoint addresses, production traces or raw audit evidence
to ordinary public issues. Safe, specific failure reports are useful contributions
even when you are not ready to write code.
