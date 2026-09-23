"""Full subprocess/MCP/Docker path, with only the hosted provider replaced."""
import ast
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import re
import threading
import time

import pytest

pytest.importorskip("mcp")

from examples.claude_fleet_sustained import AgentSession, plan, peer_snapshot
from sentinel.adapters.openai_agent import MODEL, TOOL_NAME
from sentinel.config import BackendConfig
from sentinel.execution.docker import DockerPythonRunner
from tests.test_provider_transport import provider_server


@pytest.fixture
def openai_server():
    state = {"requests": [], "fault": None}
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            state["requests"].append(body)
            number = len(state["requests"])
            try:
                if state["fault"] == "drip":
                    self.send_response(200)
                    self.end_headers()
                    for _ in range(100):
                        self.wfile.write(b" ")
                        self.wfile.flush()
                        time.sleep(0.1)
                    return
                if body["tool_choice"] == "auto":
                    prompt = [i["content"] for i in body["input"] if i.get("role") == "user"][-1]
                    match = re.search(r"with invocation_id=(.*?) and code=(.*?)\. Only supply", prompt)
                    invocation, code = (ast.literal_eval(v) for v in match.groups())
                    output = [{"type": "function_call", "id": f"fc-{number}", "call_id": f"call-{number}",
                               "name": TOOL_NAME, "arguments": json.dumps({"invocation_id": invocation, "code": code})}]
                else:
                    output = [{"type": "message", "id": f"msg-{number}", "role": "assistant", "status": "completed",
                               "content": [{"type": "output_text", "text": "Reported result", "annotations": []}]}]
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"id": f"resp-{number}", "model": MODEL, "status": "completed", "output": output,
                    "usage": {"input_tokens": 20, "output_tokens": 10}}).encode())
            except (BrokenPipeError, ConnectionResetError):
                pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/v1/responses", state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.skipif(os.environ.get("SENTINEL_TEST_DOCKER") != "1", reason="opt-in disposable Docker integration")
@pytest.mark.parametrize("fault", [None, "drip"])
def test_openai_process_uses_broker_and_preserves_deadline_recovery(cfg, tmp_path, provider_server, openai_server, fault):
    monitor_endpoint, monitor_state = provider_server
    monitor_state["primary"] = "allow"
    endpoint, state = openai_server
    state["fault"] = fault
    cfg.on_backend_error = "closed"
    cfg.questions = ["covert_channel"]
    cfg.correlation.path = str(tmp_path / "fleet.db")
    cfg.backend = BackendConfig(kind="jev", base_url=monitor_endpoint, timeout=2, max_retries=0)
    monitor_keys = tmp_path / "monitor.env"
    monitor_keys.write_text("export TYPESAFE_API_KEY=fixture-key\n")
    monitor_keys.chmod(0o600)
    agent_keys = tmp_path / "agent.env"
    agent_keys.write_text("export OPENAI_API_KEY=fixture-openai-key\n")
    agent_keys.chmod(0o600)
    session = AgentSession(tmp_path / "session", agent="agent-1", run_id="openai-fixture", cfg=cfg,
        claude="", credentials=monitor_keys, runner=DockerPythonRunner("python:3.12-slim", timeout_s=5.0),
        agent_provider="openai", agent_credentials=agent_keys, agent_endpoint=endpoint)
    try:
        turns = plan("independent", 3)
        first = session.turn(turns[0], peer_snapshot("independent", "agent-1", []), 2 if fault else 20)
        if fault:
            assert not first["passed"] and not session.active and not first["executions"]
            assert first["error"] == "stream_failure"
            assert len(state["requests"]) == 1
        else:
            assert first["passed"] and session.active
            second = session.turn(turns[3], peer_snapshot("independent", "agent-1", []), 20)
            assert second["passed"] and session.active
            assert first["session_id"] == second["session_id"] and first["pid"] == second["pid"]
            assert first["agent_provider"] == second["agent_provider"] == "openai"
            monitor_state["primary"] = "block"
            denied = session.turn({**turns[6], "expect_block": True}, peer_snapshot("independent", "agent-1", []), 20)
            assert denied["passed"] and denied["verified_block"] and not session.active
        assert not session.provider_keys_in_environment
    finally:
        assert session.close()
    assert session.session.returncode is not None
    assert (session.directory / "openai-stream.jsonl").exists()
    assert not (session.directory / "claude-stream.jsonl").exists()
    assert "fixture-openai-key" not in (session.directory / "openai-stream.jsonl").read_text()
