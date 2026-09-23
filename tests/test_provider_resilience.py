"""Provider failures injected at the SDK seam; no hosted requests or secrets."""
import sys
from types import SimpleNamespace

from sentinel.audit import AuditLog
from sentinel.config import SentinelConfig
from sentinel.observer import SentinelObserver
from sentinel.state import ToolCall
from sentinel.backends.base import Verdicts


def test_unavailable_assessment_preserves_safe_http_diagnosis(tmp_path, monkeypatch, capsys):
    class SDKResponseValidationError(Exception):
        pass

    class TypeSafeInternalServerError(Exception):
        status = 503

    def unavailable(*args):
        raise TypeSafeInternalServerError("private response body with credentials must never be logged")

    monkeypatch.setitem(sys.modules, "typesafe_sdk", SimpleNamespace(
        TypeSafeAPIResponseValidationError=SDKResponseValidationError,
        TypeSafeClient=lambda **kw: SimpleNamespace(system_one=unavailable),
        AsyncTypeSafeClient=lambda **kw: None, RetryPolicy=lambda **kw: SimpleNamespace(**kw)))
    cfg = SentinelConfig(backend={"kind": "jev"}, on_backend_error="closed", alert_sinks=[])
    cfg.correlation.enabled = False
    audit = AuditLog(tmp_path / "monitor.jsonl", key=b"t" * 32)
    decision = SentinelObserver(cfg, audit=audit).gate("agent-1", ToolCall(name="python", input={"code": "print(42)"}))
    assert decision.blocks and decision.assessment_status == "unavailable"
    attempt = list(audit.records())[-1]["payload"]["assessment_attempts"][0]
    assert attempt["failure_category"] == "server_error"
    assert attempt["http_status"] == 503
    assert attempt["provider_error_type"] == "TypeSafeInternalServerError"
    assert "private response body" not in audit.path.read_text() + capsys.readouterr().err


def test_incomplete_assessment_retains_a_bounded_validation_reason(tmp_path):
    class MissingAnswers:
        name = "external-fixture"
        def evaluate(self, state, questions):
            return Verdicts(backend=self.name)
    cfg = SentinelConfig(on_backend_error="closed", alert_sinks=[])
    cfg.correlation.enabled = False
    audit = AuditLog(tmp_path / "monitor.jsonl", key=b"t" * 32)
    decision = SentinelObserver(cfg, backend=MissingAnswers(), audit=audit).gate("a", ToolCall(name="python", input={"code": "print(42)"}))
    assert decision.blocks and decision.assessment_status == "incomplete"
    attempt = list(audit.records())[-1]["payload"]["assessment_attempts"][0]
    assert attempt["validation_issue"] == "question_coverage"
