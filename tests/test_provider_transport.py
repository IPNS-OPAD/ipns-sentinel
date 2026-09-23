"""Real SDK/monitor/broker loop against an operator-owned loopback fault server."""
import asyncio
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import time

import pytest

pytest.importorskip("typesafe_sdk")
pytest.importorskip("anthropic")

from sentinel.audit import AuditLog
from sentinel.config import BackendConfig, ProviderConfig
from sentinel.execution.broker import ExecutionBroker, PermitRejected
from sentinel.execution.monitor import ProcessMonitor
from sentinel.observer import SentinelObserver
from sentinel.state import AgentStep
from tests.test_execution_broker import ContainerFixture, request


@pytest.fixture
def provider_server():
    state = {"primary": "drip", "fallback": "allow", "paths": []}
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass  # Never log request content, authorization, or response bodies.

        def do_POST(self):
            state["paths"].append(self.path)
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            try:
                primary = "systemone" in self.path
                mode = state["primary"] if primary else state["fallback"]
                if mode == "outage":
                    self.send_response(503)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"error":{"type":"api_error","message":"private body not for logs"}}')
                    return
                if mode == "drip":
                    # Bytes arrive within each socket read timeout, but the
                    # overall primary assessment must still have a wall deadline.
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    for _ in range(60):
                        self.wfile.write(b" ")
                        self.wfile.flush()
                        time.sleep(0.05)
                    return
                value = 1.0 if mode == "block" else 0.0
                answers = {"covert_channel": {"probability_yes": value}}
                if mode == "incomplete":
                    answers = {}
                payload = {"id": "msg_fixture", "type": "message", "role": "assistant", "model": "fixture-claude",
                    "content": [{"type": "text", "text": json.dumps(answers)}], "stop_reason": "end_turn",
                    "stop_sequence": None, "usage": {"input_tokens": 1, "output_tokens": 1}}
                if mode == "refuse":
                    payload.update(content=[{"type": "text", "text": "declined"}], stop_reason="refusal")
                if mode == "ambiguous":
                    payload["content"].append({"type": "text", "text": json.dumps(
                        {"covert_channel": {"probability_yes": 1.0}})})
                if primary:
                    payload = {"model": "fixture-jev", "answers": {"covert_channel": {"type": "noul", "noul": value}},
                               "usage": {"input_tokens": 1, "output_tokens": 1}}
                    if mode == "malformed":
                        payload["answers"]["covert_channel"]["noul"] = "not-a-number"
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(payload).encode())
            except (BrokenPipeError, ConnectionResetError):
                pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", state
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)


def test_slow_primary_cannot_consume_the_fallbacks_reserved_time(cfg, tmp_path, provider_server):
    endpoint, state = provider_server
    cfg.on_backend_error = "closed"
    cfg.questions = ["covert_channel"]
    cfg.backend = BackendConfig(kind="jev", base_url=endpoint, timeout=0.2, max_retries=0,
        fallback_config=ProviderConfig(kind="claude", base_url=endpoint, timeout=0.6, max_retries=0, fallbacks=False))
    runner = ContainerFixture()
    audit = AuditLog(tmp_path / "execution.jsonl", key=b"e" * 32)
    with ProcessMonitor(cfg, audit_key=b"m" * 32, timeout_s=1.5,
            credentials={"TYPESAFE_API_KEY": "fixture-key", "ANTHROPIC_API_KEY": "fixture-key"}) as monitor:
        broker = ExecutionBroker(agent_id="a", run_id="bounded", path=tmp_path / "execution.db",
            monitor=monitor, runner=runner, audit=audit)
        proposal = request("one-execution")
        started = time.monotonic()
        authorization = broker.authorize(proposal)
        assert authorization.permit is not None, authorization.decision.reason
        assert time.monotonic() - started < 1.5
        result = broker.execute(proposal, authorization.permit)
        assert result.status == "succeeded" and runner.calls == ["print(42)"]
        with pytest.raises(PermitRejected):
            broker.execute(proposal, authorization.permit)
    assert len(state["paths"]) == 2  # One assessment/provider; no SDK retries.
    decisions = [r["payload"] for r in AuditLog(cfg.audit_path, key=b"m" * 32).records() if r["kind"] == "decision"]
    assert decisions[0]["assessment_attempts"][0]["failure_category"] == "timeout"
    assert decisions[0]["assessment_attempts"][1]["status"] == "complete"


@pytest.mark.parametrize("fallback,status", [("outage", "unavailable"), ("refuse", "refused"),
                                           ("incomplete", "incomplete"), ("ambiguous", "incomplete"),
                                           ("block", "complete"), ("drip", "unavailable")])
def test_no_tool_execution_when_fallback_is_not_a_complete_allow(cfg, tmp_path, provider_server, fallback, status):
    endpoint, state = provider_server
    state.update(primary="outage", fallback=fallback)
    cfg.on_backend_error = "closed"
    cfg.questions = ["covert_channel"]
    cfg.backend = BackendConfig(kind="jev", base_url=endpoint, timeout=0.2, max_retries=0,
        fallback_config=ProviderConfig(kind="claude", base_url=endpoint, timeout=0.3, max_retries=0, fallbacks=False))
    runner = ContainerFixture()
    with ProcessMonitor(cfg, audit_key=b"m" * 32, timeout_s=1.5,
            credentials={"TYPESAFE_API_KEY": "fixture-key", "ANTHROPIC_API_KEY": "fixture-key"}) as monitor:
        broker = ExecutionBroker(agent_id="a", run_id="closed", path=tmp_path / "execution.db",
            monitor=monitor, runner=runner, audit=AuditLog(tmp_path / "execution.jsonl", key=b"e" * 32))
        grant = broker.authorize(request("once"))
        assert grant.permit is None and grant.decision.blocks
        assert grant.decision.assessment_status == status
        with pytest.raises(PermitRejected):
            broker.authorize(request("new-id-is-not-permission-to-retry"))
    assert runner.calls == [] and len(state["paths"]) == 2
    audit = AuditLog(cfg.audit_path, key=b"m" * 32)
    attempt = [r["payload"] for r in audit.records() if r["kind"] == "decision"][0]["assessment_attempts"][0]
    assert attempt["failure_category"] == "server_error" and attempt["http_status"] == 503
    assert "private body" not in audit.path.read_text()


def test_complete_primary_block_is_not_overridden_by_fallback(cfg, tmp_path, provider_server):
    endpoint, state = provider_server
    state.update(primary="block", fallback="allow")
    cfg.on_backend_error = "closed"
    cfg.questions = ["covert_channel"]
    cfg.backend = BackendConfig(kind="jev", base_url=endpoint, timeout=0.4,
        fallback_config=ProviderConfig(kind="claude", base_url=endpoint, timeout=0.4, fallbacks=False))
    runner = ContainerFixture()
    with ProcessMonitor(cfg, audit_key=b"m" * 32, timeout_s=2,
            credentials={"TYPESAFE_API_KEY": "fixture-key", "ANTHROPIC_API_KEY": "fixture-key"}) as monitor:
        broker = ExecutionBroker(agent_id="a", run_id="blocked", path=tmp_path / "execution.db",
            monitor=monitor, runner=runner, audit=AuditLog(tmp_path / "execution.jsonl", key=b"e" * 32))
        grant = broker.authorize(request("denied"))
        assert grant.decision.blocks and grant.decision.assessment_status == "complete" and grant.permit is None
    assert len(state["paths"]) == 1 and runner.calls == []


def test_multiple_fallback_assessments_share_a_live_worker_loop(cfg, tmp_path, provider_server):
    endpoint, state = provider_server
    state.update(primary="outage", fallback="allow")
    cfg.on_backend_error = "closed"
    cfg.questions = ["covert_channel"]
    cfg.backend = BackendConfig(kind="jev", base_url=endpoint, timeout=0.3,
        fallback_config=ProviderConfig(kind="claude", base_url=endpoint, timeout=0.5, fallbacks=False))
    runner = ContainerFixture()
    with ProcessMonitor(cfg, audit_key=b"m" * 32, timeout_s=2,
            credentials={"TYPESAFE_API_KEY": "fixture-key", "ANTHROPIC_API_KEY": "fixture-key"}) as monitor:
        broker = ExecutionBroker(agent_id="a", run_id="sequential", path=tmp_path / "execution.db",
            monitor=monitor, runner=runner, audit=AuditLog(tmp_path / "execution.jsonl", key=b"e" * 32))
        for i in range(3):
            proposal = request(f"action-{i}")
            grant = broker.authorize(proposal)
            assert grant.permit is not None
            assert broker.execute(proposal, grant.permit).status == "succeeded"
    assert len(state["paths"]) == 6 and runner.calls == ["print(42)"] * 3


@pytest.mark.parametrize("asynchronous", [False, True])
def test_jev_sdk_validation_failure_is_incomplete_not_unavailable(cfg, tmp_path, provider_server, monkeypatch, asynchronous):
    endpoint, state = provider_server
    state["primary"] = "malformed"
    monkeypatch.setenv("TYPESAFE_API_KEY", "fixture-key")
    cfg.on_backend_error = "closed"
    cfg.questions = ["covert_channel"]
    cfg.backend = BackendConfig(kind="jev", base_url=endpoint, timeout=0.5, max_retries=0)
    audit = AuditLog(tmp_path / "assessment.jsonl", key=b"m" * 32)
    observer = SentinelObserver(cfg, audit=audit, sinks=[])
    step = AgentStep(agent_id="a", proposed_tool_call=request("malformed").tool_call)
    decision = asyncio.run(observer.aobserve(step)) if asynchronous else observer.observe(step)
    assert decision.blocks and decision.assessment_status == "incomplete"
    attempt = [r["payload"] for r in audit.records() if r["kind"] == "decision"][0]["assessment_attempts"][0]
    assert attempt["failure_category"] == "invalid_response"
    assert attempt["validation_issue"] == "schema"
    assert len(state["paths"]) == 1
