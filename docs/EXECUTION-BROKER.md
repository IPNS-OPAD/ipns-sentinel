# Experimental Python execution broker

The generic wrappers run inside the agent application. The optional broker adds a
separate monitor process, exact-call authorization and disposable Python containers.
It remains a local experimental integration, not a complete host security boundary.

## Trust boundary

The trusted operator fixes policy, agent/run identities, signing keys, image,
resources and lifecycle. Agent requests supply an invocation identifier, Python
code and untrusted exposed reasoning/peer context—not their own permissions.

Allowed calls receive short-lived one-use permits bound to their exact arguments
and run. The broker persists consumption before execution. Reused, changed,
expired or stale permits cannot authorize another execution. Uncertain outcomes
are not permission to retry: this is at-most-once admission, not exactly-once
external effects.

The first Docker runner has no host mounts, no network or supplied secrets, a
read-only root filesystem, an unprivileged user and bounded resources/output.
The Python image must already be present; no image is pulled automatically.
The operator must isolate the agent from the host account, Docker socket,
monitor configuration, signing keys and evidence storage. A same-user library
object is not an access-control barrier.

## Interfaces

`sentinel broker --help` describes the JSONL interface and trusted launch options.
An operator creates the closed-policy configuration and audit key outside agent
control. The agent receives only its broker input/output channel, never host
credentials or the Docker control plane.

The optional `.[harness]` extra enables `sentinel broker --transport mcp` and the
single `run_python` tool. Permit issuance/consumption stay inside that adapter;
the model does not receive the permit. The restricted Claude Code profile removes
native tools in a dedicated session, but still trusts the host runtime and managed
settings. Existing unrestricted sessions are not automatically protected.

Repository examples are opt-in developer harnesses. Some invoke hosted agent or
monitor APIs and may incur charges. Read the selected script's CLI help and data
flow before running it. Keep all generated evidence private. The generic demo
is the key-free first step.

## Limits and verification

Monitor loss, incomplete assessments and expired deadlines deny admission. A hold
revokes pending permits and attempts cleanup; failed cleanup requires operator
review. Cancellation cannot guarantee instantaneous interruption after admission.
Host/process failure, lost protected state, Docker/kernel compromise and durable
external effects remain separate deployment concerns.

The current executor intentionally exposes no network, filesystem mounts or
persistent task artifacts. Productive file/network adapters need their own
authorization rules and effect collection. Independent custody of audit evidence
and actual OS separation must be verified in the deployment.

Run local broker/monitor tests with `uv run pytest -q tests/test_process_monitor.py
tests/test_execution_broker.py tests/test_execution_mcp.py`. Opt-in real container
checks use `SENTINEL_TEST_DOCKER=1 uv run pytest -q tests/test_docker_execution.py
tests/test_docker_mcp.py`. These use disposable test containers, not hosted models.
Fake-scored tests establish control flow, not detector quality.
