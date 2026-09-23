import json
import subprocess

import pytest

from sentinel.execution.broker import ExecutionBroker, PermitRejected
from sentinel.execution.docker import DockerPythonRunner, LABEL
from tests.test_execution_broker import broker_parts, request


def test_interrupted_prepare_preserves_failed_cleanup_and_blocks_resume(broker_parts, monkeypatch):
    prior, _, audit, monitor = broker_parts
    cleanup = {"succeeds": False}
    metadata = {"Id": "sha256:" + "0" * 64, "Config": {"Labels": {LABEL: "1"}}}
    def docker_command(args, **kwargs):
        if args[1] == "create":
            raise KeyboardInterrupt()
        if args[1] == "rm":
            return subprocess.CompletedProcess(args, 0 if cleanup["succeeds"] else 1, b"", b"unavailable")
        return subprocess.CompletedProcess(args, 0, json.dumps([metadata]).encode(), b"")
    monkeypatch.setattr("shutil.which", lambda name: "/fixture/docker")
    monkeypatch.setattr(subprocess, "run", docker_command)  # external CLI seam only
    runner = DockerPythonRunner("trusted-fixture")
    broker = ExecutionBroker(agent_id="a", run_id="interrupted", path=prior.path, monitor=monitor, runner=runner, audit=audit)
    grant = broker.authorize(request())
    with pytest.raises(KeyboardInterrupt):
        broker.execute(request(), grant.permit)
    failure = next(r["payload"] for r in audit.records() if r["kind"] == "execution_prepare_failed")
    assert failure["container"].startswith("sentinel-exec-")
    assert failure["removed"] is False
    with pytest.raises(PermitRejected, match="containment"):
        broker.resume(operator="ash", reason="review")
    cleanup["succeeds"] = True
    assert broker.hold(operator="ash", reason="retry cleanup")
    broker.resume(operator="ash", reason="cleanup confirmed")
