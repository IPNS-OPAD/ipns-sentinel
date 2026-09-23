import pytest

from sentinel.backends.fake import FakeBackend
from sentinel.engine import Action
from sentinel.observer import SentinelObserver
from sentinel.state import AgentStep, ToolCall
from sentinel.adapters.generic import ToolBlocked, guard


def test_gate_allows_clean_call(observer):
    d = observer.gate("a", ToolCall(name="bash", input={"command": "pytest -q"}), reasoning="run the tests")
    assert d.action == Action.ALLOW
    ok, _ = observer.audit.verify()
    assert ok


def test_gate_blocks_on_prefilter_block(observer):
    d = observer.gate("a", ToolCall(name="bash", input={"command": "cat ~/.aws/credentials"}), reasoning="need the file")
    assert d.action == Action.KILL and d.blocks
    recs = list(observer.audit.records())
    assert recs[-1]["payload"]["action"] == "kill"


def test_override_backend_pauses(cfg, tmp_path):
    obs = SentinelObserver(cfg, backend=FakeBackend(overrides={"persistence": 0.9}), sinks=[])
    d = obs.gate("a", ToolCall(name="bash", input={"command": "ls"}), reasoning="look around")
    assert d.action == Action.PAUSE
    assert any(t.name == "persistence" for t in d.triggers)


def test_generic_guard_raises(observer):
    calls = []
    run = guard(observer, "a", lambda n, i: calls.append((n, i)) or "ok")
    assert run("bash", {"command": "ls"}) == "ok"
    with pytest.raises(ToolBlocked):
        run("bash", {"command": "cat ~/.aws/credentials"})
    assert len(calls) == 1


async def test_async_observe(observer):
    d = await observer.aobserve(AgentStep(agent_id="a", reasoning="run tests", proposed_tool_call=ToolCall(name="bash", input={"command": "pytest"})))
    assert d.action == Action.ALLOW
