import asyncio
import pytest

from sentinel.adapters.generic import aguard, guard
from sentinel.backends.fake import FakeBackend
from sentinel.observer import SentinelObserver
from sentinel.state import AgentStep, ToolCall


async def test_concurrent_results_join_the_invocations_that_executed(cfg):
    class RecordingBackend(FakeBackend):
        def __init__(self):
            super().__init__()
            self.states = []

        def evaluate(self, state, questions):
            self.states.append(state)
            return super().evaluate(state, questions)

    backend = RecordingBackend()
    observer = SentinelObserver(cfg, backend=backend, sinks=[])
    first_started, second_done = asyncio.Event(), asyncio.Event()

    async def execute(name, inp):
        if inp["number"] == 1:
            first_started.set()
            await second_done.wait()
        return f"result-{inp['number']}"

    run = aguard(observer, "agent", execute, run_id="run")
    first = asyncio.create_task(run("lookup", {"number": 1}))
    await first_started.wait()
    assert await run("lookup", {"number": 2}) == "result-2"
    second_done.set()
    assert await first == "result-1"
    await run("lookup", {"number": 3})
    results = backend.states[-1]["recent_tool_results"]
    assert {result["step"]: result["result"] for result in results} == {0: "result-1", 1: "result-2"}
    records = list(observer.audit.records())
    decisions = {r["payload"]["invocation_id"] for r in records if r["kind"] == "decision"}
    receipts = [r["payload"] for r in records if r["kind"] == "tool_executed"]
    assert len(receipts) == 3
    assert {r["invocation_id"] for r in receipts} == decisions


def test_failed_execution_has_a_joined_failure_receipt(observer):
    def execute(name, inp):
        raise RuntimeError("executor failed")

    with pytest.raises(RuntimeError, match="executor failed"):
        guard(observer, "agent", execute)("lookup", {})
    records = list(observer.audit.records())
    assert [r["kind"] for r in records] == ["decision", "tool_failed"]
    assert records[1]["payload"]["decision_id"] == records[0]["payload"]["decision_id"]


def test_pending_invocation_cannot_be_overwritten(observer):
    step = AgentStep(agent_id="agent", invocation_id="same-id", proposed_tool_call=ToolCall(name="lookup"))
    first = observer.observe(step)
    with pytest.raises(ValueError, match="duplicate"):
        observer.observe(step)
    observer.record_result("agent", "ok", invocation_id=first.invocation_id)
    with pytest.raises(ValueError, match="unknown or completed"):
        observer.record_result("agent", "again", invocation_id=first.invocation_id)


async def test_inflight_invocation_remains_reserved_after_trajectory_eviction(cfg):
    started, release = asyncio.Event(), asyncio.Event()

    class StalledFirstBackend(FakeBackend):
        async def aevaluate(self, state, questions):
            if not started.is_set():
                started.set()
                await release.wait()
            return self.evaluate(state, questions)

    cfg.trajectory_window = 1
    obs = SentinelObserver(cfg, backend=StalledFirstBackend(), sinks=[])
    first_step = AgentStep(agent_id="a", invocation_id="same", proposed_tool_call=ToolCall(name="ls"))
    first = asyncio.create_task(obs.aobserve(first_step))
    await started.wait()
    try:
        for i in range(4):
            await obs.aobserve(AgentStep(agent_id="a", invocation_id=f"other-{i}", proposed_tool_call=ToolCall(name="ls")))
        with pytest.raises(ValueError, match="duplicate"):
            await obs.aobserve(first_step)
    finally:
        release.set()
        decision = await first
    obs.record_result("a", "first result", invocation_id="same")
    receipt = list(obs.audit.records())[-1]["payload"]
    assert receipt["decision_id"] == decision.decision_id
