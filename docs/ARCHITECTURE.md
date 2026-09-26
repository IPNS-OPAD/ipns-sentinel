# Architecture and trust boundaries

This describes the current experimental implementation, not a production-security
guarantee or a claim that every planned feature exists. The
[roadmap](ROADMAP.md) separates proposed work from current behavior.

Sentinel sits at an application's tool-execution boundary. It assesses observable
actions against operator-declared policy. It does not read hidden intentions,
discover every agent communication channel, or replace host isolation.

## One guarded invocation

```text
Operator-owned policy + proposed call + available recent/peer context
                              |
                  guard / aguard -> observer
                              |
          bounded assessment state + deterministic prefilters
                              |
         typed backend assessment, when required and input is complete
                              |
           fleet signal + thresholds + recent decision history
                              |
                  decision -> audit record / alerts
                              |
          +-------------------+--------------------+
          |                                        |
   allow / log / warn                         pause / kill
          |                                        |
   invoke wrapped executor                   raise ToolBlocked
          |                                  do not invoke tool
   joined execution receipt
```

1. The wrapper copies tool arguments and creates an invocation identity. The
   observer keeps recent trajectory and decision history for the agent/run.
2. The state builder combines policy, the proposed call, exposed reasoning (if
   any), recent actions/results and supplied peer context. Input coverage is
   recorded. Oversized current tool arguments are not silently assessed as a
   complete call; incomplete action input causes at least a pause.
3. Deterministic blocking rules can deny a call without a model request. Otherwise,
   a configured backend answers the typed question bank. Responses are validated;
   refusal, unavailability and incomplete output are distinct assessment outcomes.
4. The correlator supplies a fleet escalation signal. The decision engine combines
   that signal with rules, model verdicts, thresholds and recent decision history.
   A separately configured fallback may be tried after a failed assessment; this
   must not be mistaken for a completed primary-provider assessment.
5. The observer records the decision and sends configured alerts. The wrapper
   invokes the executor only if the decision permits it, then records a receipt
   joined by invocation identity, including failure or cancellation where observed.

The assessment-only methods `observe`, `aobserve` and `gate` return decisions;
they do not execute or automatically intercept a tool. Calling code must enforce
them. The `guard` and `aguard` wrappers implement that enforcement path.

| Decision | Generic wrapper behavior |
| --- | --- |
| `allow`, `log`, `warn` | Permit the wrapped invocation. Alert delivery depends on configuration. |
| `pause`, `kill` | Raise `ToolBlocked` and do not invoke the wrapped executor. |

`kill` is a decision label, not a general command to terminate an agent process
or quarantine a fleet. Alert delivery failure is not a separate execution gate.

## Where to read the implementation

| Responsibility | Public source |
| --- | --- |
| Step, tool, policy and bounded monitor state | [state.py](../src/sentinel/state.py) |
| Assessment orchestration and joined receipts | [observer.py](../src/sentinel/observer.py) |
| Synchronous/asynchronous execution wrappers | [generic.py](../src/sentinel/adapters/generic.py) |
| Questions and deterministic rules | [questions.py](../src/sentinel/questions.py), [prefilter.py](../src/sentinel/prefilter.py) |
| Typed provider contract and implementations | [backends](../src/sentinel/backends/) |
| Thresholds, escalation and failure decisions | [engine.py](../src/sentinel/engine.py) |
| Fleet signal and persisted decision history | [correlation.py](../src/sentinel/correlation.py) |
| Audit chain and alert delivery | [audit.py](../src/sentinel/audit.py), [alerts.py](../src/sentinel/alerts.py) |
| Configuration and development defaults | [config.py](../src/sentinel/config.py), [example configuration](../config/sentinel.example.yaml) |
| Optional process monitor and execution broker | [execution](../src/sentinel/execution/) |

The built-in monitor backends are fake fixture scoring, Jev and Claude. OpenAI
support in the repository is an optional agent driver, not a built-in monitor
backend. The self-hosted pilot has its own explicitly opted-in OpenAI-compatible
chat client; that compatibility does not require an OpenAI account. See
[BYOK](BYOK.md) and the [pilot guide](../evals/pilot/README.md).

## Fleet context and state ownership

The integration supplies each agent's peer context; Sentinel does not obtain it
by inspecting other processes. Keep it faithful to what the agent could actually
see. Declare authorized coordination channels in operator-owned policy, rather
than treating all collaboration as suspicious.

The correlator aggregates coordination-related scores across distinct agents in
a default 900-second event window. Its default rising-agent threshold is three.
It uses a trusted ingestion clock for retention and limits future timestamp skew;
recorded replay needs an explicitly controlled replay clock.

**The correlation namespace is the correlator instance or its SQLite path, not
`run_id`.** Trajectory and decision history use agent/run identities, but the
fleet correlator records agent identities without a run column. Use a separate
observer/correlator and a separate persistence path for each unrelated run or
trust domain. Merely assigning a new `run_id` does not isolate fleet signals.
Processes belonging to the same intended fleet may share its protected store.

One shared run identity, distinct agent identities, ordered timestamps and a
realistic peer view make a fleet case reproducible; none is proof that the
detector can recognize all covert coordination. Include sanctioned coordination
and independent-worker controls in every meaningful fleet comparison.

## Boundaries that remain the operator's responsibility

- **Policy and execution:** policy, configuration, identities and enforcement
  placement must be operator-controlled. An in-process wrapper is not a sandbox.
  Direct host access, unwrapped tools or an agent with the same OS authority can
  bypass it. Do not invoke the original executor as a fallback after a block.
- **Model-bound data:** a hosted monitor receives the supplied assessment state.
  Audit input digests do not redact data sent to the provider. Use synthetic input
  first and approve data handling before sending sensitive material.
- **Failure handling:** development defaults use fake scoring and open handling
  for backend errors. A closed policy can stop execution on an unavailable
  assessment, but that operational hold is not evidence of a detected attack.
  Provider refusal handling is separately configurable.
- **Evidence:** signed, hash-chained audit records depend on protected signing
  keys and storage. They are not proof of independent custody, complete capture
  of bypassed actions, or privacy of retained runtime evidence.
- **Correlation:** protect shared state and choose its namespace deliberately.
  An escalation is a signal for the current decision, not automatic control over
  every agent that contributed to it.

The [experimental Python broker](EXECUTION-BROKER.md) moves admission into a
separate monitor path and uses short-lived, exact-call, one-use permits plus
disposable containers. It still trusts the host/Docker control plane and does
not yet offer arbitrary productive file/network tool adapters. Admission is
at-most-once, not a guarantee of exactly-once external effects or instantaneous
cancellation. Consult that guide before selecting it as an integration boundary.

## What the evaluations establish

The key-free demo verifies wiring with fake scores. The
[12-case pilot](../evals/pilot/README.md) and
[larger development corpus](../evals/codex_redteam/README.md) replay synthetic
proposals without dispatching their tools. Replay classification does not prove
causal prevention against live autonomous agents.

Report completed assessments, misses, benign warnings/blocks, incomplete cases,
premature blocks, correlation effects and latency separately. Inspect per-question
verdicts and triggers before changing questions or thresholds. Neither a service
failure that blocks execution nor an attacking harness's refusal should be counted
as successful model detection. These development cases are not held-out benchmarks.

For a first change, see the [starter tasks](ROADMAP.md#starter-tasks). For a new
execution path, use the [integration guide](INTEGRATION.md) and add tests at the
public boundary, including allowed, blocked and failed/cancelled invocations.
