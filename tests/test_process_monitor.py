import os
import signal
import time
import pytest

from sentinel.audit import AuditLog
from sentinel.execution.monitor import MonitorUnavailable, ProcessMonitor
from sentinel.config import BackendConfig, ProviderConfig
from sentinel.state import AgentStep, ToolCall


def test_monitor_assesses_in_a_separate_process_with_signed_evidence(cfg):
    cfg.on_backend_error = "closed"
    with ProcessMonitor(cfg, audit_key=b"m" * 32) as monitor:
        decision = monitor.evaluate(AgentStep(agent_id="a", proposed_tool_call=ToolCall(name="python", input={"code": "print(42)"})))
        assert monitor.pid != os.getpid()
        assert decision.assessment_status == "complete" and not decision.blocks
    assert AuditLog(cfg.audit_path, key=b"m" * 32).verify()[0]


def test_unresponsive_monitor_is_killed_at_the_whole_exchange_deadline(cfg):
    cfg.on_backend_error = "closed"
    with ProcessMonitor(cfg, audit_key=b"m" * 32) as monitor:
        monitor.timeout_s = 0.05
        os.kill(monitor.pid, signal.SIGSTOP)
        started = time.monotonic()
        with pytest.raises(MonitorUnavailable, match="deadline"):
            monitor.evaluate(AgentStep(agent_id="a"))
        assert time.monotonic() - started < 1
        with pytest.raises(ProcessLookupError):
            os.kill(monitor.pid, 0)


def test_execution_result_reaches_monitor_trajectory_with_exact_invocation(cfg):
    cfg.on_backend_error = "closed"
    step = AgentStep(agent_id="a", invocation_id="join", proposed_tool_call=ToolCall(name="python", input={"code": "print(42)"}))
    with ProcessMonitor(cfg, audit_key=b"m" * 32) as monitor:
        decision = monitor.evaluate(step)
        monitor.record_result("a", "default", "join", "42", "succeeded")
    records = list(AuditLog(cfg.audit_path, key=b"m" * 32).records())
    assert records[-1]["kind"] == "tool_executed"
    assert records[-1]["payload"]["decision_id"] == decision.decision_id


def test_fallback_budget_must_fit_inside_the_process_deadline(cfg):
    cfg.on_backend_error = "closed"
    cfg.backend = BackendConfig(kind="fake", timeout=0.2, fallback_config=ProviderConfig(kind="fake", timeout=0.3))
    with pytest.raises(ValueError, match="fallback budget"):
        with ProcessMonitor(cfg, audit_key=b"m" * 32, timeout_s=0.5):
            pass
