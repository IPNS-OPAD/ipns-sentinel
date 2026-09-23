import sys
import pytest

from examples import claude_code_smoke
from sentinel.audit import AuditLog
from sentinel.config import SentinelConfig, BackendConfig
from tests.test_execution_broker import ContainerFixture


@pytest.mark.parametrize("with_fallback", [False, True])
def test_credential_file_disappearing_after_launch_cannot_skip_recovery(tmp_path, monkeypatch, with_fallback):
    credentials = tmp_path / "temporary-credentials"
    credentials.write_text("export TYPESAFE_API_KEY=test-jev\n")
    credentials.chmod(0o600)
    # External Claude fixture exits without a tool call and removes only this
    # test's disposable credential file. No hosted service or real Docker used.
    claude = tmp_path / "claude-fixture"
    claude.write_text(f"#!{sys.executable}\nfrom pathlib import Path\nPath({str(credentials)!r}).unlink()\n")
    claude.chmod(0o700)
    class RunnerFixture(ContainerFixture):
        image = "fixture-image"
    monkeypatch.setattr(claude_code_smoke, "DockerPythonRunner", lambda *a, **kw: RunnerFixture())
    cfg = SentinelConfig(backend=BackendConfig(kind="jev"), on_backend_error="closed")
    if with_fallback:
        cfg.backend = BackendConfig(kind="jev", timeout=3, fallback_config={"kind": "claude", "timeout": 20})
    root = tmp_path / "evidence"
    root.mkdir()
    result = claude_code_smoke.run_case(root, "rotation", "print(42)", blocked=False,
        claude=str(claude), image="fixture-image", config=cfg, credentials=credentials)
    assert not result["passed"]  # Missing proposal is still failed coverage.
    key = (root / "rotation" / "audit.key").read_bytes()
    audit = AuditLog(root / "rotation" / "execution.jsonl", key=key)
    assert audit.verify()[0]
    assert any(r["kind"] == "run_stopped" and r["payload"]["state"] == "terminated" for r in audit.records())
