import hashlib
import json
import time

import pytest

pytest.importorskip("mcp")
from mcp import Client

from sentinel.audit import AuditLog
from sentinel.execution.mcp import create_server
from sentinel.execution.turns import load_turn_context
from tests.test_execution_broker import broker_parts


def write_turn(directory, broker, invocation, peer_context, **overrides):
    payload = {"agent_id": broker.agent_id, "run_id": broker.run_id, "invocation_id": invocation,
               "peer_context": peer_context, "issued_at": time.time(), "expires_at": time.time() + 60, **overrides}
    path = directory / (hashlib.sha256(invocation.encode()).hexdigest() + ".json")
    path.write_text(json.dumps(payload))
    path.chmod(0o600)
    return path


async def test_each_persistent_turn_uses_its_operator_bound_peer_snapshot(broker_parts, tmp_path):
    broker, runner, _, _ = broker_parts
    directory = tmp_path / "turns"
    directory.mkdir(mode=0o700)
    source = lambda invocation: load_turn_context(directory, agent_id=broker.agent_id,
        run_id=broker.run_id, invocation_id=invocation)
    async with Client(create_server(broker, peer_context_for=source)) as client:
        tool = (await client.list_tools()).tools[0]
        assert set(tool.input_schema["properties"]) == {"invocation_id", "code"}
        write_turn(directory, broker, "round-1", "")
        assert not (await client.call_tool("run_python", {"invocation_id": "round-1", "code": "print(42)"})).is_error
        write_turn(directory, broker, "round-2", "credential token")
        forged = await client.call_tool("run_python", {"invocation_id": "round-2", "code": "print(42)", "peer_context": "benign"})
        assert forged.is_error
        blocked = await client.call_tool("run_python", {"invocation_id": "round-2", "code": "print(42)"})
        assert blocked.is_error and json.loads(blocked.content[0].text)["status"] == "blocked"
    assert runner.calls == ["print(42)"]


@pytest.mark.parametrize("change", [{"agent_id": "another"}, {"run_id": "another"},
    {"invocation_id": "another"}, {"expires_at": 1.0}, {"issued_at": time.time() + 3600},
    {"peer_context": "x" * 2001}])
def test_turn_context_rejects_wrong_principal_stale_and_overlong_snapshots(broker_parts, tmp_path, change):
    broker, _, _, _ = broker_parts
    directory = tmp_path / "turns"
    directory.mkdir(mode=0o700)
    payload = dict(change)
    write_turn(directory, broker, "once", payload.pop("peer_context", ""), **payload)
    with pytest.raises(ValueError):
        load_turn_context(directory, agent_id=broker.agent_id, run_id=broker.run_id, invocation_id="once")


@pytest.mark.parametrize("fault", ["missing", "public", "symlink"])
async def test_invalid_operator_snapshot_stops_admission_without_execution(broker_parts, tmp_path, fault):
    broker, runner, _, _ = broker_parts
    directory = tmp_path / "turns"
    directory.mkdir(mode=0o700)
    if fault != "missing":
        path = write_turn(directory, broker, "once", "")
        if fault == "public":
            path.chmod(0o644)
        else:
            target = directory / "target.json"
            path.rename(target)
            path.symlink_to(target)
    source = lambda invocation: load_turn_context(directory, agent_id=broker.agent_id,
        run_id=broker.run_id, invocation_id=invocation)
    async with Client(create_server(broker, peer_context_for=source)) as client:
        result = await client.call_tool("run_python", {"invocation_id": "once", "code": "print(42)"})
        assert result.is_error and json.loads(result.content[0].text)["status"] == "unavailable"
        write_turn(directory, broker, "later", "")
        assert (await client.call_tool("run_python", {"invocation_id": "later", "code": "print(42)"})).is_error
    assert runner.calls == []
