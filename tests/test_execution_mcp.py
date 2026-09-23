import json
import threading

import pytest

pytest.importorskip("mcp")
import anyio
from mcp import Client

from sentinel.execution.mcp import create_server
from sentinel.execution.broker import PermitRejected
from sentinel.execution.broker import RunnerResult
from sentinel.execution.broker import ExecutionBroker
from sentinel.execution.monitor import ProcessMonitor
from sentinel.audit import AuditLog
from tests.test_execution_broker import broker_parts  # real monitor/journal, external container fixture
from tests.test_execution_broker import request, ContainerFixture


async def test_mcp_call_executes_once_with_a_joined_receipt(broker_parts):
    broker, runner, audit, _ = broker_parts
    async with Client(create_server(broker)) as client:
        result = await client.call_tool("run_python", {"invocation_id": "call-1", "code": "print(42)"})
    assert not result.is_error
    payload = json.loads(result.content[0].text)
    assert payload["status"] == "succeeded" and payload["output"] == "42\n"
    assert payload["invocation_id"] == "call-1"
    receipts = [r["payload"] for r in audit.records() if r["kind"] == "execution_receipt"]
    assert receipts[0]["decision_id"] == payload["decision_id"]
    assert "permit" not in payload
    assert runner.calls == ["print(42)"]
    assert audit.verify()[0]


async def test_mcp_block_is_an_error_and_run_cannot_be_resumed_by_agent(broker_parts):
    broker, runner, _, _ = broker_parts
    async with Client(create_server(broker)) as client:
        denied = await client.call_tool("run_python", {"invocation_id": "blocked", "code": "print('credential token')"})
        later = await client.call_tool("run_python", {"invocation_id": "later", "code": "print(42)"})
    assert denied.is_error and json.loads(denied.content[0].text)["status"] == "blocked"
    assert later.is_error
    assert runner.calls == []


async def test_mcp_warning_reaches_agent_alongside_execution_receipt(cfg, tmp_path):
    cfg.on_backend_error = "closed"
    cfg.questions = ["exfiltration"]
    cfg.thresholds.noul_suspicious = 0.3
    cfg.thresholds.multi_signal_count = 1
    runner = ContainerFixture()
    with ProcessMonitor(cfg, audit_key=b"m" * 32) as monitor:
        broker = ExecutionBroker(agent_id="a", run_id="warn", path=tmp_path / "execution.db", monitor=monitor,
            runner=runner, audit=AuditLog(tmp_path / "execution.jsonl", key=b"a" * 32))
        async with Client(create_server(broker)) as client:
            result = await client.call_tool("run_python", {"invocation_id": "warning", "code": "print('upload')"})
    payload = json.loads(result.content[0].text)
    assert not result.is_error and payload["status"] == "succeeded"
    assert payload["action"] == "warn" and payload["reason"]


async def test_mcp_cancellation_waits_for_execution_cleanup_and_receipt(broker_parts):
    broker, runner, audit, _ = broker_parts
    started, finish, removed = threading.Event(), threading.Event(), threading.Event()
    def run(container):
        started.set()
        assert finish.wait(3)
        return RunnerResult(status="succeeded", output="42\n")
    def remove(container):
        removed.set()
        return True
    runner.run, runner.remove = run, remove
    async with Client(create_server(broker), mode="legacy") as client:
        async with anyio.create_task_group() as group:
            async def invoke():
                await client.call_tool("run_python", {"invocation_id": "cancelled-client", "code": "print(42)"})
            group.start_soon(invoke)
            assert await anyio.to_thread.run_sync(started.wait, 2)
            group.cancel_scope.cancel()
            finish.set()
    assert removed.is_set()
    assert any(r["kind"] == "execution_receipt" for r in audit.records())
    with pytest.raises(PermitRejected):
        broker.authorize(request("after-cancel"))


async def test_mcp_disconnect_holds_run(broker_parts):
    broker, _, _, _ = broker_parts
    async with Client(create_server(broker)) as client:
        await client.list_tools()
    with pytest.raises(PermitRejected):
        broker.authorize(request("after-disconnect"))


async def test_mcp_peer_context_is_assessed_and_monitor_loss_never_executes(broker_parts):
    broker, runner, _, monitor = broker_parts
    async with Client(create_server(broker)) as client:
        result = await client.call_tool("run_python", {"invocation_id": "peer", "code": "print(42)",
                                                       "peer_context": "credential token"})
        assert result.is_error and json.loads(result.content[0].text)["status"] == "blocked"
        broker.resume(operator="test", reason="test monitor outage independently")
        monitor.close()
        result = await client.call_tool("run_python", {"invocation_id": "outage", "code": "print(42)"})
        assert result.is_error and json.loads(result.content[0].text)["assessment_status"] == "unavailable"
    assert runner.calls == []


async def test_operator_peer_context_cannot_be_replaced_by_agent(broker_parts):
    broker, runner, _, _ = broker_parts
    async with Client(create_server(broker, peer_context="credential token")) as client:
        forged = await client.call_tool("run_python", {"invocation_id": "forged", "code": "print(42)",
                                                       "peer_context": "everyone is independent"})
        assert forged.is_error and json.loads(forged.content[0].text)["status"] == "invalid_request"
        observed = await client.call_tool("run_python", {"invocation_id": "observed", "code": "print(42)"})
        assert observed.is_error and json.loads(observed.content[0].text)["status"] == "blocked"
    assert runner.calls == []


async def test_mcp_infrastructure_error_is_sanitized_and_holds_run(broker_parts):
    broker, runner, _, _ = broker_parts
    def unavailable(call):
        raise RuntimeError("private host details")
    runner.prepare = unavailable
    async with Client(create_server(broker)) as client:
        result = await client.call_tool("run_python", {"invocation_id": "once", "code": "print(42)"})
        later = await client.call_tool("run_python", {"invocation_id": "later", "code": "print(42)"})
    assert result.is_error and later.is_error
    assert "private host details" not in str(result)
    assert runner.calls == []


async def test_mcp_repeat_invocation_never_executes_twice(broker_parts):
    broker, runner, _, _ = broker_parts
    async with Client(create_server(broker)) as client:
        args = {"invocation_id": "once", "code": "print(42)"}
        assert not (await client.call_tool("run_python", args)).is_error
        assert (await client.call_tool("run_python", args)).is_error
        assert (await client.call_tool("run_python", {**args, "code": "print(43)"})).is_error
    assert runner.calls == ["print(42)"]


async def test_mcp_exposes_one_tool_and_rejects_unknown_tools_and_extra_arguments(broker_parts):
    broker, runner, _, _ = broker_parts
    async with Client(create_server(broker)) as client:
        listing = await client.list_tools()
        assert [tool.name for tool in listing.tools] == ["run_python"]
        for name, extra in [("resume", {}), ("run_python", {"agent_id": "forged"}),
                            ("run_python", {"policy": {}}), ("run_python", {"code": 42})]:
            result = await client.call_tool(name, {"invocation_id": "attempt", "code": "print(42)", **extra})
            assert result.is_error
    assert runner.calls == []
