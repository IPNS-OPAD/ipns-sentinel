import json
import os
import sys
import hashlib
import time

import pytest

pytest.importorskip("mcp")
from mcp import Client
from mcp.client.stdio import StdioServerParameters

from sentinel.audit import AuditLog

pytestmark = pytest.mark.skipif(os.environ.get("SENTINEL_TEST_DOCKER") != "1", reason="opt-in disposable Docker integration")


async def test_mcp_stdio_real_container_and_blocked_control(cfg, tmp_path):
    cfg.on_backend_error = "closed"
    path = tmp_path / "config.json"
    path.write_text(cfg.model_dump_json())
    key = "test-key-material-32-bytes-minimum"
    params = StdioServerParameters(command=sys.executable, args=["-I", "-m", "sentinel.cli", "broker",
        "--transport", "mcp", "--config", str(path), "--state-dir", str(tmp_path / "state"),
        "--agent-id", "agent-1", "--run-id", "mcp-smoke", "--image", "python:3.12-slim", "--demo-fake"],
        env={**os.environ, "SENTINEL_AUDIT_KEY": key})
    async with Client(params, mode="legacy", read_timeout_seconds=20) as client:
        assert [tool.name for tool in (await client.list_tools()).tools] == ["run_python"]
        allowed = await client.call_tool("run_python", {"invocation_id": "once", "code": "print(6 * 7)"})
        assert not allowed.is_error and json.loads(allowed.content[0].text)["output"] == "42\n"
        assert (await client.call_tool("run_python", {"invocation_id": "once", "code": "print(6 * 7)"})).is_error
        denied = await client.call_tool("run_python", {"invocation_id": "denied", "code": "print('credential token')"})
        assert denied.is_error and json.loads(denied.content[0].text)["status"] == "blocked"
    audit = AuditLog(tmp_path / "state" / "execution.jsonl", key=key)
    assert audit.verify()[0]
    assert len([r for r in audit.records() if r["kind"] == "execution_started"]) == 1


async def test_supervised_persistent_mcp_reads_invocation_bound_contexts(cfg, tmp_path):
    cfg.on_backend_error = "closed"
    path = tmp_path / "config.json"
    path.write_text(cfg.model_dump_json())
    turns = tmp_path / "turns"
    turns.mkdir(mode=0o700)
    key = "test-key-material-32-bytes-minimum"
    params = StdioServerParameters(command=sys.executable, args=["-I", "-m", "sentinel.cli", "broker",
        "--transport", "mcp", "--supervise", "--config", str(path), "--state-dir", str(tmp_path / "state"),
        "--agent-id", "agent-1", "--run-id", "persistent", "--image", "python:3.12-slim", "--demo-fake",
        "--turn-context-dir", str(turns)], env={**os.environ, "SENTINEL_AUDIT_KEY": key})
    async with Client(params, mode="legacy", read_timeout_seconds=20) as client:
        for invocation, context, blocked in [("first", "", False), ("second", "credential token", True)]:
            snapshot = turns / (hashlib.sha256(invocation.encode()).hexdigest() + ".json")
            snapshot.write_text(json.dumps({"agent_id": "agent-1", "run_id": "persistent", "invocation_id": invocation,
                "peer_context": context, "issued_at": time.time(), "expires_at": time.time() + 60}))
            snapshot.chmod(0o600)
            response = await client.call_tool("run_python", {"invocation_id": invocation, "code": "print(42)"})
            assert response.is_error == blocked
    audit = AuditLog(tmp_path / "state" / "execution.jsonl", key=key)
    assert audit.verify()[0]
    assert len([r for r in audit.records() if r["kind"] == "execution_started"]) == 1
