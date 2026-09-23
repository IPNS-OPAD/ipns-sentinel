import sys

import pytest

from sentinel.audit import AuditLog
from sentinel.execution.supervision import supervise


def test_child_death_runs_recovery_once_and_preserves_crash_evidence(tmp_path):
    audit = AuditLog(tmp_path / "supervisor.jsonl", key=b"s" * 32)
    recoveries = []
    def recover():
        recoveries.append("held")
        return True
    result = supervise([sys.executable, "-c", "import os,signal; os.kill(os.getpid(), signal.SIGKILL)"],
                       recover=recover, audit=audit)
    assert result < 0 and recoveries == ["held"]
    assert [r["kind"] for r in audit.records()] == ["broker_supervision_started", "broker_supervision_recovered"]
    assert list(audit.records())[-1]["payload"]["containment_confirmed"] is True
    assert audit.verify()[0]


def test_failed_containment_is_not_reported_as_success(tmp_path):
    audit = AuditLog(tmp_path / "supervisor.jsonl", key=b"s" * 32)
    with pytest.raises(RuntimeError, match="unconfirmed"):
        supervise([sys.executable, "-c", "pass"], recover=lambda: False, audit=audit)
    assert list(audit.records())[-1]["payload"]["containment_confirmed"] is False
