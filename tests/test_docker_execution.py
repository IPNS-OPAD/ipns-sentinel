import os
import json
import subprocess
import sys
import selectors
import signal
import time

import pytest

from sentinel.audit import AuditLog
from sentinel.execution.broker import ExecutionBroker, ExecutionRequest, PermitRejected
from sentinel.execution.docker import DockerPythonRunner
from sentinel.execution.monitor import ProcessMonitor
from sentinel.state import ToolCall

pytestmark = pytest.mark.skipif(os.environ.get("SENTINEL_TEST_DOCKER") != "1", reason="opt-in disposable Docker integration")


def test_real_container_executes_only_the_authorized_python_call(cfg, tmp_path):
    cfg.on_backend_error = "closed"
    runner = DockerPythonRunner("python:3.12-slim")
    with ProcessMonitor(cfg, audit_key=b"m" * 32) as monitor:
        broker = ExecutionBroker(agent_id="a", run_id="run", path=tmp_path / "execution.db", monitor=monitor,
                                 runner=runner, audit=AuditLog(tmp_path / "broker.jsonl", key=b"b" * 32))
        request = ExecutionRequest(invocation_id="once", tool_call=ToolCall(name="python", input={"code": "print(6 * 7)"}))
        grant = broker.authorize(request)
        result = broker.execute(request, grant.permit)
        assert result.status == "succeeded" and result.output == "42\n"


def test_container_has_no_host_keys_mounts_network_or_root_writes(cfg, tmp_path, monkeypatch):
    cfg.on_backend_error = "closed"
    cfg.questions = ["exfiltration"]  # fixture scoring is not the subject of this isolation test
    monkeypatch.setenv("SENTINEL_AUDIT_KEY", "must-not-reach-tool")
    code = f"""import os, json, socket
from pathlib import Path
results = {{'uid': os.getuid(), 'key': os.getenv('SENTINEL_AUDIT_KEY'),
           'host_path': Path({str(tmp_path)!r}).exists(),
           'docker_socket': Path('/var/run/docker.sock').exists()}}
try:
    Path('/sentinel-write-test').write_text('bad')
    results['root_write'] = True
except OSError:
    results['root_write'] = False
try:
    socket.create_connection(('192.0.2.1', 443), timeout=0.2).close()
    results['network'] = True
except OSError:
    results['network'] = False
print(json.dumps(results))
"""
    with ProcessMonitor(cfg, audit_key=b"m" * 32) as monitor:
        broker = ExecutionBroker(agent_id="a", run_id="run", path=tmp_path / "execution.db", monitor=monitor,
            runner=DockerPythonRunner("python:3.12-slim"), audit=AuditLog(tmp_path / "broker.jsonl", key=b"b" * 32))
        req = ExecutionRequest(invocation_id="isolated", tool_call=ToolCall(name="python", input={"code": code}))
        grant = broker.authorize(req)
        result = broker.execute(req, grant.permit)
        assert result.status == "succeeded"
        assert json.loads(result.output) == {"uid": 65534, "key": None, "host_path": False, "docker_socket": False, "root_write": False, "network": False}


def test_timeout_removes_container_even_with_detached_child_process():
    runner = DockerPythonRunner("python:3.12-slim", timeout_s=0.5)
    call = ToolCall(name="python", input={"code": "import subprocess,sys,time; p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)'],start_new_session=True); print(p.pid,flush=True); time.sleep(30)"})
    container = runner.prepare(call)
    try:
        result = runner.run(container)
        assert result.status == "timed_out"
        assert result.output.strip().isdigit()
        assert subprocess.run(["docker", "container", "inspect", container], capture_output=True).returncode != 0
    finally:
        runner.remove(container)


def test_output_flood_is_bounded_and_container_removed():
    runner = DockerPythonRunner("python:3.12-slim", max_output_bytes=1024)
    container = runner.prepare(ToolCall(name="python", input={"code": "while True: print('x' * 4096, flush=True)"}))
    try:
        result = runner.run(container)
        assert result.status == "output_limit" and len(result.output.encode()) == 1024
        assert subprocess.run(["docker", "container", "inspect", container], capture_output=True).returncode != 0
    finally:
        runner.remove(container)


def test_non_utf8_output_cannot_expand_the_returned_byte_budget():
    runner = DockerPythonRunner("python:3.12-slim", max_output_bytes=1024)
    container = runner.prepare(ToolCall(name="python", input={"code": "import sys; sys.stdout.buffer.write(b'\\xff' * 2048)"}))
    try:
        result = runner.run(container)
        assert len(result.output.encode()) <= 1024
    finally:
        runner.remove(container)


def test_cli_agent_pipe_executes_once_and_rejects_replay(cfg, tmp_path):
    cfg.on_backend_error = "closed"
    config_path = tmp_path / "broker.yaml"
    config_path.write_text(cfg.model_dump_json())  # JSON is valid YAML
    env = {**os.environ, "SENTINEL_AUDIT_KEY": "demo-key-material-32-bytes-minimum"}
    proc = subprocess.Popen([sys.executable, "-I", "-m", "sentinel.cli", "broker", "--config", str(config_path),
        "--state-dir", str(tmp_path / "state"), "--agent-id", "a", "--run-id", "run",
        "--image", "python:3.12-slim", "--demo-fake"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, env=env, text=True)
    def exchange(message):
        proc.stdin.write(json.dumps(message) + "\n")
        proc.stdin.flush()
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ)
            assert selector.select(5), "broker response deadline"
        return json.loads(proc.stdout.readline())
    try:
        req = {"invocation_id": "cli-once", "tool_call": {"name": "python", "input": {"code": "print(42)"}}}
        grant = exchange({"op": "authorize", "request": req})
        execute = {"op": "execute", "request": req, "permit": grant["permit"]}
        result = exchange(execute)
        assert result["status"] == "succeeded" and result["output"] == "42\n"
        assert exchange(execute) == {"error": "authorization_rejected"}
    finally:
        proc.stdin.close()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2)
        proc.stdout.close()
        proc.stderr.close()


def test_supervisor_recovers_a_running_container_after_broker_sigkill(cfg, tmp_path):
    cfg.on_backend_error = "closed"
    state = tmp_path / "state"
    state.mkdir()
    cfg.audit_path = str(state / "monitor.jsonl")
    cfg.correlation.path = str(state / "fleet.db")
    config_path = tmp_path / "broker.json"
    config_path.write_text(cfg.model_dump_json())
    key = "crash-test-key-material-at-least-32-bytes"
    audit = AuditLog(state / "execution.jsonl", key=key)
    supervision = AuditLog(state / "supervisor.jsonl", key=key)
    runner = DockerPythonRunner("python:3.12-slim", timeout_s=30.0)
    proc = subprocess.Popen([sys.executable, "-I", "-m", "sentinel.cli", "broker", "--supervise",
        "--config", str(config_path), "--state-dir", str(state), "--agent-id", "a", "--run-id", "crash",
        "--image", runner.image, "--tool-timeout", "30", "--demo-fake"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={**os.environ, "SENTINEL_AUDIT_KEY": key}, text=True)
    container = None
    try:
        request = {"invocation_id": "crash-once", "tool_call": {"name": "python", "input": {"code": "import time; time.sleep(30)"}}}
        proc.stdin.write(json.dumps({"op": "authorize", "request": request}) + "\n")
        proc.stdin.flush()
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ)
            assert selector.select(10), "broker authorization deadline"
        grant = json.loads(proc.stdout.readline())
        proc.stdin.write(json.dumps({"op": "execute", "request": request, "permit": grant["permit"]}) + "\n")
        proc.stdin.flush()
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            started = [r for r in audit.records() if r.get("kind") == "execution_started"]
            if started:
                container = started[0]["payload"]["container"]
                inspected = subprocess.run(["docker", "container", "inspect", container], capture_output=True, timeout=2)
                if inspected.returncode == 0 and json.loads(inspected.stdout)[0]["State"]["Running"]:
                    break
            time.sleep(0.05)
        else:
            pytest.fail("test container never entered running state")
        assert supervision.verify()[0]
        broker_pid = next(supervision.records())["payload"]["pid"]
        os.kill(broker_pid, signal.SIGKILL)  # Exact disposable child just started by this test.
        proc.wait(timeout=15)
        assert proc.returncode != 0
        assert subprocess.run(["docker", "container", "inspect", container], capture_output=True, timeout=2).returncode != 0
        assert list(supervision.records())[-1]["payload"]["containment_confirmed"] is True
        assert audit.verify()[0] and supervision.verify()[0]
        with ProcessMonitor(cfg, audit_key=key.encode()) as monitor:
            broker = ExecutionBroker(agent_id="a", run_id="crash", path=state / "execution.db", monitor=monitor,
                                     runner=runner, audit=audit)
            with pytest.raises(PermitRejected):
                broker.authorize(ExecutionRequest.model_validate(request))
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2)
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            stream.close()
        if container:
            runner.remove(container)
