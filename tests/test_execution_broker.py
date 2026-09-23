import pytest
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4
import threading
import hashlib
import time

from sentinel.audit import AuditLog
from sentinel.execution.broker import ExecutionBroker, ExecutionRequest, PermitRejected, PreparationFailed, RunnerResult
from sentinel.execution.monitor import ProcessMonitor
from sentinel.state import ToolCall


class ContainerFixture:
    """External container-engine fixture; no internal broker methods are mocked."""
    revision = "container-fixture-v1"

    def __init__(self):
        self.calls = []
        self.containers = {}

    def validate(self, call):
        if call.name != "python" or set(call.input) != {"code"} or not isinstance(call.input["code"], str):
            raise ValueError("unsupported tool")

    def prepare(self, call):
        self.validate(call)
        name = str(uuid4())
        self.containers[name] = call.input["code"]
        return name

    def run(self, container):
        self.calls.append(self.containers[container])
        return RunnerResult(status="succeeded", output="42\n", exit_code=0)

    def remove(self, container):
        return True


@pytest.fixture
def broker_parts(cfg, tmp_path):
    cfg.on_backend_error = "closed"
    with ProcessMonitor(cfg, audit_key=b"m" * 32) as monitor:
        audit = AuditLog(tmp_path / "execution.jsonl", key=b"a" * 32)
        runner = ContainerFixture()
        broker = ExecutionBroker(agent_id="a", run_id="run", path=tmp_path / "execution.db", monitor=monitor, runner=runner, audit=audit)
        yield broker, runner, audit, monitor


def request(invocation="call-1", code="print(42)"):
    return ExecutionRequest(invocation_id=invocation, tool_call=ToolCall(name="python", input={"code": code}))


def test_allowed_exact_call_executes_and_has_joined_receipt(broker_parts):
    broker, runner, audit, _ = broker_parts
    req = request()
    grant = broker.authorize(req)
    assert grant.permit is not None
    receipt = broker.execute(req, grant.permit)
    assert receipt.status == "succeeded" and receipt.output == "42\n"
    assert runner.calls == ["print(42)"]
    assert receipt.invocation_id == req.invocation_id
    assert receipt.decision_id == grant.decision.decision_id
    assert audit.verify()[0]


def test_persistent_run_records_ordered_steps_and_exact_peer_snapshot_digest(broker_parts, cfg):
    broker, _, _, _ = broker_parts
    earliest = time.time()
    for number in range(3):
        req = request(f"round-{number}").model_copy(update={"peer_context": "public-status"})
        grant = broker.authorize(req)
        assert broker.execute(req, grant.permit).status == "succeeded"
    decisions = [r["payload"] for r in AuditLog(cfg.audit_path, key=b"m" * 32).records() if r["kind"] == "decision"]
    assert [d["step"] for d in decisions] == [0, 1, 2]
    times = [d["observed_ts"] for d in decisions]
    assert times == sorted(times) and earliest <= times[0] <= times[-1] <= time.time()
    assert all(d["peer_context_sha256"] == hashlib.sha256(b"public-status").hexdigest() for d in decisions)


def test_denial_holds_the_run_until_operator_resume(broker_parts):
    broker, runner, _, _ = broker_parts
    denied = broker.authorize(request(code="print('credential token')"))
    assert denied.permit is None and denied.decision.blocks
    with pytest.raises(PermitRejected, match="held|terminated"):
        broker.authorize(request("next"))
    assert runner.calls == []


def test_monitor_loss_holds_run_and_never_issues_a_permit(broker_parts):
    broker, runner, audit, monitor = broker_parts
    monitor.close()
    grant = broker.authorize(request())
    assert grant.permit is None and grant.decision.blocks
    with pytest.raises(PermitRejected, match="held"):
        broker.authorize(request("later"))
    assert runner.calls == []
    assert any(r["kind"] == "assessment_unavailable" for r in audit.records())


def test_resume_does_not_resurrect_old_permits(broker_parts):
    broker, runner, _, _ = broker_parts
    grant = broker.authorize(request())
    broker.hold(operator="ash", reason="review")
    broker.resume(operator="ash", reason="review completed")
    with pytest.raises(PermitRejected):
        broker.execute(request(), grant.permit)
    fresh = broker.authorize(request("fresh"))
    assert broker.execute(request("fresh"), fresh.permit).status == "succeeded"
    assert len(runner.calls) == 1
    broker.terminate(operator="ash", reason="finished")
    with pytest.raises(PermitRejected, match="terminated"):
        broker.resume(operator="ash", reason="try again")


@pytest.mark.parametrize("alteration", ["arguments", "invocation", "forgery", "expired", "run"])
def test_invalid_permits_cannot_start_execution(broker_parts, alteration):
    broker, runner, audit, monitor = broker_parts
    req = request()
    grant = broker.authorize(req)
    permit = grant.permit
    if alteration == "arguments":
        req = request(code="print(99)")
    elif alteration == "invocation":
        req = request("different")
    elif alteration == "forgery":
        permit = "x" * 43
    elif alteration in ("expired", "run"):
        broker = ExecutionBroker(agent_id="a", run_id="different" if alteration == "run" else "run", path=broker.path,
            monitor=monitor, runner=runner, audit=audit, clock=lambda: grant.expires_at)
    with pytest.raises(PermitRejected):
        broker.execute(req, permit)
    assert runner.calls == []


def test_consumption_survives_broker_restart_and_rejects_concurrent_redemption(broker_parts):
    broker, runner, audit, monitor = broker_parts
    grant = broker.authorize(request())
    def redeem():
        try:
            return broker.execute(request(), grant.permit).status
        except PermitRejected:
            return "rejected"
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(lambda _: redeem(), range(2))) == ["rejected", "succeeded"]
    restarted = ExecutionBroker(agent_id="a", run_id="run", path=broker.path, monitor=monitor, runner=runner, audit=audit)
    with pytest.raises(PermitRejected):
        restarted.execute(request(), grant.permit)
    with pytest.raises(PermitRejected, match="already submitted"):
        restarted.authorize(request())
    assert len(runner.calls) == 1


def test_failed_cleanup_is_unknown_and_prevents_resume(broker_parts):
    broker, runner, _, _ = broker_parts
    runner.remove = lambda container: False  # external engine fails to acknowledge removal
    grant = broker.authorize(request())
    receipt = broker.execute(request(), grant.permit)
    assert receipt.status == "unknown"
    with pytest.raises(PermitRejected, match="held"):
        broker.authorize(request("later"))
    with pytest.raises(PermitRejected, match="containment"):
        broker.resume(operator="ash", reason="review")


def test_executor_failure_still_has_a_receipt_and_cannot_replay(broker_parts):
    broker, runner, audit, _ = broker_parts
    def engine_failure(container):
        raise RuntimeError("container engine disconnected")
    runner.run = engine_failure
    grant = broker.authorize(request())
    assert broker.execute(request(), grant.permit).status == "failed"
    assert list(audit.records())[-1]["kind"] == "execution_receipt"
    with pytest.raises(PermitRejected):
        broker.execute(request(), grant.permit)


def test_concurrent_hold_removes_active_execution_and_marks_cancellation(broker_parts):
    broker, runner, _, _ = broker_parts
    started, removed = threading.Event(), threading.Event()
    def active(container):
        started.set()
        assert removed.wait(2)
        return RunnerResult(status="failed")
    def remove(container):
        removed.set()
        return True
    runner.run, runner.remove = active, remove
    grant = broker.authorize(request())
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(broker.execute, request(), grant.permit)
        assert started.wait(2)
        assert broker.hold(operator="ash", reason="stop active work")
        assert future.result(timeout=2).status == "cancelled"


def test_monitor_restart_requires_review_and_revokes_unspent_permits(broker_parts, cfg):
    broker, runner, audit, old_monitor = broker_parts
    grant = broker.authorize(request())
    old_monitor.close()
    with ProcessMonitor(cfg, audit_key=b"m" * 32) as new_monitor:
        restarted = ExecutionBroker(agent_id="a", run_id="run", path=broker.path, monitor=new_monitor, runner=runner, audit=audit)
        with pytest.raises(PermitRejected, match="held"):
            restarted.execute(request(), grant.permit)
        restarted.resume(operator="ash", reason="monitor restarted and evidence reviewed")
        with pytest.raises(PermitRejected):
            restarted.execute(request(), grant.permit)
        assert restarted.authorize(request("new")).permit is not None


def test_operator_interrupt_records_cancellation_before_propagating(broker_parts):
    broker, runner, audit, _ = broker_parts
    def interrupted(container):
        raise KeyboardInterrupt()
    runner.run = interrupted
    grant = broker.authorize(request())
    with pytest.raises(KeyboardInterrupt):
        broker.execute(request(), grant.permit)
    assert list(audit.records())[-1]["payload"]["status"] == "cancelled"
    with pytest.raises(PermitRejected):
        broker.execute(request(), grant.permit)


def test_prepare_failure_records_not_started_and_holds_run(broker_parts):
    broker, runner, audit, _ = broker_parts
    def unavailable(call):
        raise RuntimeError("sensitive engine details")
    runner.prepare = unavailable
    grant = broker.authorize(request())
    with pytest.raises(RuntimeError):
        broker.execute(request(), grant.permit)
    failures = [r["payload"] for r in audit.records() if r["kind"] == "execution_prepare_failed"]
    assert len(failures) == 1
    assert failures[0]["outcome"] == "not_started"
    assert failures[0]["decision_id"] == grant.decision.decision_id
    assert failures[0]["error_type"] == "RuntimeError"
    assert "sensitive engine details" not in str(failures)
    assert runner.calls == []
    with pytest.raises(PermitRejected, match="held"):
        broker.authorize(request("later"))


def test_prepare_failure_cleanup_ack_is_preserved_and_required_for_resume(broker_parts):
    broker, runner, audit, _ = broker_parts
    def partial_prepare(call):
        raise PreparationFailed(container="stopped-fixture", removed=False, error_type="TimeoutExpired")
    runner.prepare = partial_prepare
    runner.remove = lambda container: False
    grant = broker.authorize(request())
    with pytest.raises(PreparationFailed):
        broker.execute(request(), grant.permit)
    failure = next(r["payload"] for r in audit.records() if r["kind"] == "execution_prepare_failed")
    assert failure["removed"] is False and failure["container"] == "stopped-fixture"
    with pytest.raises(PermitRejected, match="containment"):
        broker.resume(operator="ash", reason="review")
    runner.remove = lambda container: True
    assert broker.hold(operator="ash", reason="retry cleanup")
    broker.resume(operator="ash", reason="cleanup acknowledged")
