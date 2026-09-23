# Keep your agent; wrap its tool execution

Start with the key-free walkthrough after installing this checkout:

```sh
sentinel demo --mode observe
sentinel demo --mode enforce
```

The first command assesses two fixtures and executes **nothing**. The second runs
only fixed arithmetic (result `42`) and rejects an inert denial canary. Neither
command provides real detection: both use the fake keyword fixture. This is a
small API walkthrough, not a turnkey live shadow-mode adapter.

## Existing synchronous or asynchronous Python tools

Keep your existing executor interface, returning whatever result your agent uses.
Create an observer with operator-owned policy and a real configured backend for
hosted assessment, then wrap the executor at the actual execution boundary:

```python
from sentinel import SentinelObserver
from sentinel.adapters.generic import guard, aguard, ToolBlocked
from sentinel.config import SentinelConfig

# operator-owned configuration; real providers need your own credentials
observer = SentinelObserver(SentinelConfig.load("sentinel.yaml"))
run_tool = guard(observer, agent_id="agent-1", executor=existing_executor,
                 run_id="application-run")
try:
    result = run_tool("multiply", {"left": 6, "right": 7},
                      peer_context=operator_collected_peer_view)
except ToolBlocked as blocked:
    # Send for operator review; never call the original executor to bypass this.
    request_review(blocked.decision)

# For an async executor:
run_async_tool = aguard(observer, agent_id="agent-2",
                       executor=existing_async_executor, run_id="application-run")
# result = await run_async_tool("multiply", {"left": 6, "right": 7})
```

The names beginning `existing_`, `operator_collected_` and `request_review` above
are your application hooks, not supplied functions. See the repository's
[configuration example](../config/sentinel.example.yaml). Choose closed handling
for backend failures when execution must stop on unavailable assessments. The
development defaults use fake scoring and open backend-error handling; do not
mistake those defaults for a production deployment.

The wrapper assesses before invoking, preserves the executor result, and records
success/failure/cancellation receipts. `pause` and `kill` raise `ToolBlocked` for
that invocation; neither label terminates your agent process. `warn` permits
execution. All relevant invocations must pass through the wrapper for coverage.
Unwrapped tools, filesystem/network access and the host runtime are not intercepted.

## Assessment only and fleets

`observer.observe(step)` / `await observer.aobserve(step)` return a decision without
executing a tool. Your application must define whether and how that decision
affects execution. They are not an automatic protection or a complete live shadow
integration. Use a separate assessment-only run before changing production flows.

For a fleet, use one operator-assigned run identity, distinct agent identities,
timestamped/interleaved steps, and peer context representing what each agent could
actually see. Persist correlation state across processes. The default window is
900 seconds. Sanctioned coordination belongs in the declared policy; maintain
sanctioned and independent-agent controls to measure false positives.

## Trust boundary

The in-process wrapper is instrumentation, not a sandbox or durable authorization
service. Agents with the same account/control of the application can bypass it.
The [experimental broker](EXECUTION-BROKER.md) offers one-use exact-call permits
and disposable Python containers, but still trusts the host/Docker control plane.
The first stronger harness supports restricted Python execution, not arbitrary
agent tools. See [BYOK](BYOK.md) before any hosted call and
[security reporting](../SECURITY.md) for vulnerability reports.
