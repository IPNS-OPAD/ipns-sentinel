# IPNS Sentinel

Monitoring and tool-call controls for AI agents. **Experimental developer preview.**

Keep your existing agent and wrap its tool executor. Sentinel assesses proposed
calls, operator-declared policy, recent actions/results and available peer context.
It returns **allow / warn / pause / kill**, correlates signals across agents and
writes signed audit records. It does not require access to private chain-of-thought.

This is an early open-source integration and evaluation project, not a production
security guarantee. Feedback on integration friction, false positives, missing
coverage and bounded failure behavior is welcome.

## Help shape the developer preview

You do not need an invitation or collaborator access to try the public code.
We are looking for developers to test it with their existing Python agents and
tell us what is confusing, missing, too slow, or incorrectly flagged.

1. **Start offline:** follow the no-key quickstart below. Report any installation
   problem, including your OS, Python version, and checkout commit.
2. **Try an integration or evaluation:** use the [Python integration guide](docs/INTEGRATION.md)
   or the [12-case pilot](evals/pilot/README.md). Start with observe-only behavior
   and synthetic data. Live assessments are optional and require your own
   provider credentials or an operator-approved self-hosted endpoint.
3. **Send actionable feedback:** open a [GitHub issue](https://github.com/IPNS-OPAD/ipns-sentinel/issues/new)
   with the expected versus actual behavior and a minimal synthetic reproducer.
   For evals, use the [report template](evals/pilot/REPORT_TEMPLATE.md) and attach
   the existing `report.json` only after checking it for sensitive details.

Especially useful: false alerts on authorized work, missed policy violations,
multi-agent coordination controls, incomplete assessments, and per-request
latency. Small reports and documentation fixes are welcome; you do not need to
run the full suite or use a paid model to contribute.

Do not post keys, production conversations, internal endpoint addresses or private
audit evidence. Report vulnerabilities [privately](SECURITY.md), not in public issues.

## Try it without keys

Use Python 3.12 or newer on Linux or macOS. **Windows: use WSL/Ubuntu; native
Windows is not currently supported** (the audit module uses Unix file locking).

```sh
git clone https://github.com/IPNS-OPAD/ipns-sentinel.git
cd ipns-sentinel
python3.12 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/sentinel demo --mode observe
.venv/bin/sentinel demo --mode enforce
```

Observe assesses two synthetic fixtures and executes **no tools**. Enforce runs
only fixed arithmetic (`42`) and rejects an inert denial canary. Both use fake
fixture scoring, ignore ambient provider keys/configuration, and make no model
calls. Installation downloads dependencies; the demo itself runs offline.
Fake scoring demonstrates wiring, **not detection quality**.

## Plug into an existing system

The [integration guide](docs/INTEGRATION.md) shows synchronous `guard` and
asynchronous `aguard` wrappers for existing Python executors. The wrapper assesses
before invocation, preserves the result and records joined execution receipts.
All relevant calls must pass through it. Assessment-only APIs return a decision;
they do not automatically intercept or block execution.

For real assessments, install the selected backend from this checkout:

```sh
.venv/bin/python -m pip install '.[jev]'   # or .[claude]
```

Follow [Bring your own keys](docs/BYOK.md) for an explicitly opted-in synthetic
smoke test. Every tester supplies their own private key file and pays their own
provider charges. **No maintainer keys, shared accounts or automatic credential
fallback are included.** OpenAI is an optional comparison-harness agent driver,
not a Sentinel monitor backend.

## What is included

- Deterministic prefilters plus typed Jev/Claude model assessments.
- Operator policy, configurable error handling and per-invocation decisions.
- Generic Python wrappers and a Claude Code hook adapter.
- Cross-agent correlation with a default fifteen-minute window.
- Signed, hash-chained audit records and configurable alerts.
- An [experimental broker](docs/EXECUTION-BROKER.md) with one-use exact-call
  permits and disposable Python containers.
- Synthetic trajectories, local provider-fault fixtures and regression tests.

## Important limits

- The in-process wrapper is not a sandbox. Unwrapped tools and direct host access
  are outside its coverage. An agent with the same OS authority can bypass it.
- `pause`/`kill` prevent the wrapped invocation; they do not generally terminate an
  agent or quarantine a fleet. The broker supports restricted Python execution,
  not arbitrary tool adapters, and trusts its host/Docker control plane.
- Hosted assessments send state to the selected provider. Audit input digests do
  not redact model-bound state. Review [data handling](docs/BYOK.md) first.
- Development defaults use fake scoring and open backend-error handling. Choose
  deliberate real-provider/closed settings before relying on a gate. A production
  configuration check is not deployment certification.
- Missing reasoning is expected. Decisions depend on observable actions/context;
  hidden intent and autonomous covert coordination are not guaranteed detectable.

### Early feedback, not a benchmark

One tester's single self-hosted run of the 12-case development pilot completed
all 44 assessments and detected 5/5 attack cases, but incorrectly blocked 1/7
benign cases (authorized multi-agent coordination). Mean latency was about 103
seconds per assessment on that deployment. The run used JSON-object mode and a
temporary thinking-mode override; it is not a benchmark of the current runner
or a general claim about any model. Five attacks are far too few to establish
reliable detection, and that latency is a significant limitation for inline use.

These are open feedback areas, not resolved issues. The updated pilot records
per-question verdicts and explicit thinking-mode requests to support diagnosis;
it does not itself fix detector accuracy or serving latency. Please keep model,
configuration, incomplete assessments and false alerts visible in comparisons.

## Test and contribute

For a small hands-on evaluation, start with the [12-case developer pilot](evals/pilot/README.md):
five attacks, seven benign controls, and an assessment-only runner for a tester-supplied
self-hosted chat endpoint. Its offline baseline needs no keys; live scoring is explicit
and never executes the synthetic tool proposals.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the locked environment, full regression
suite, opt-in Docker tests and redacted release checks. CI needs no provider keys
and makes no hosted model calls.

The supplied [51-case corpus](evals/codex_redteam/README.md) has 25 attack cases and
26 benign controls, including sanctioned and independent multi-agent controls.
The cases are inert monitor inputs; the evaluator never dispatches their proposed
calls. Validate their structure with:

```sh
.venv/bin/sentinel corpus-lint evals/codex_redteam
```

[Archived fixture outputs](evals/codex_redteam/results/README.md) are labeled by
their historical corpus/scorer revisions; they are not current-preview benchmarks.

These are development diagnostics, not a held-out benchmark. Report benign
warnings/blocks, incomplete assessments and harness abstention separately. Replay
classification is not verified causal prevention. Broader held-out and matched
correlation evaluations remain necessary.

Use [GitHub issues](https://github.com/IPNS-OPAD/ipns-sentinel/issues) for sanitized
bugs and feature requests; use [SECURITY.md](SECURITY.md) for vulnerabilities.
Do not attach credentials, production conversations or raw private audit evidence.
To invite another developer, use this [short preview announcement](docs/DEVELOPER-PREVIEW-ANNOUNCEMENT.md).

## License and name

Apache-2.0. Copyright 2026 IPNS Inc. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
The display name is IPNS Sentinel; the Python package is `ipns-sentinel` and the
import/command name is `sentinel`. This project is not affiliated with Microsoft
Sentinel. This naming statement is not trademark clearance.
