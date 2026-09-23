"""Single-invocation Python containers. Docker control belongs to the operator."""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import selectors
import shutil
import subprocess
import time
from uuid import uuid4
from typing import Literal

from sentinel.execution.broker import PreparationFailed, RunnerResult
from sentinel.state import ToolCall

LABEL = "io.ipns.sentinel.execution"


class DockerPythonRunner:
    def __init__(self, image: str, *, timeout_s: float = 10, max_output_bytes: int = 65536) -> None:
        if not math.isfinite(timeout_s) or timeout_s <= 0 or not 1 <= max_output_bytes <= 1024 * 1024:
            raise ValueError("invalid execution limits")
        self._docker = shutil.which("docker")
        if self._docker is None:
            raise RuntimeError("Docker CLI is not installed")
        self._timeout, self._max_output = timeout_s, max_output_bytes
        inspected = self._command(["image", "inspect", "--", image])
        if inspected.returncode:
            raise RuntimeError("trusted image must already exist locally; no automatic pull")
        metadata = json.loads(inspected.stdout)[0]
        if metadata["Config"].get("Volumes"):
            raise ValueError("images with implicit volume mounts are not allowed")
        self.image = metadata["Id"]
        self.revision = hashlib.sha256(json.dumps(["docker-python-v1", self.image, timeout_s, max_output_bytes]).encode()).hexdigest()

    def _command(self, arguments: list[str]) -> subprocess.CompletedProcess[bytes]:
        assert self._docker is not None
        return subprocess.run([self._docker, *arguments], stdin=subprocess.DEVNULL,
                              capture_output=True, timeout=10, check=False)

    def validate(self, call: ToolCall) -> None:
        if (call.name != "python" or set(call.input) != {"code"} or not isinstance(call.input["code"], str)
                or not 1 <= len(call.input["code"].encode()) <= 32768 or "\x00" in call.input["code"]):
            raise ValueError("only python with a bounded code string is supported")

    def prepare(self, call: ToolCall) -> str:
        self.validate(call)
        name = "sentinel-exec-" + uuid4().hex
        try:
            result = self._command([
                "create", "--pull=never", "--name", name, "--label", f"{LABEL}=1",
                "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
                "--user=65534:65534", "--pids-limit=64", "--memory=256m", "--memory-swap=256m", "--cpus=1",
                "--tmpfs=/tmp:rw,noexec,nosuid,size=16m", "--workdir=/tmp", "--log-driver=none",
                "--no-healthcheck", "--entrypoint=python", self.image, "-I", "-c", call.input["code"]])
            if result.returncode:
                raise RuntimeError("container creation failed")
        except BaseException as error:
            raise PreparationFailed(container=name, removed=self.remove(name), error_type=type(error).__name__,
                                    interrupted=None if isinstance(error, Exception) else error) from error
        return name

    def run(self, container: str) -> RunnerResult:
        self._name(container)
        assert self._docker is not None
        proc = subprocess.Popen([self._docker, "start", "--attach", container], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, close_fds=True)
        assert proc.stdout is not None
        output = bytearray()
        status: Literal["succeeded", "failed", "timed_out", "unknown", "output_limit"] = "failed"
        deadline = time.monotonic() + self._timeout
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(proc.stdout, selectors.EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        status = "timed_out"
                        break
                    if not selector.select(remaining):
                        continue
                    data = os.read(proc.stdout.fileno(), 65536)
                    if not data:
                        proc.wait(timeout=max(0.01, deadline - time.monotonic()))
                        # Docker start --attach exits with the container's exit code.
                        status = "succeeded" if proc.returncode == 0 else "failed"
                        break
                    available = self._max_output - len(output)
                    output.extend(data[:available])
                    if len(data) > available:
                        status = "output_limit"
                        break
        except subprocess.TimeoutExpired:
            status = "timed_out"
        finally:
            if not self.remove(container):
                status = "unknown"
            if proc.poll() is None:
                proc.kill()
            proc.wait(timeout=2)
            proc.stdout.close()
        rendered = output.decode(errors="replace").encode()
        if len(rendered) > self._max_output and status not in ("unknown", "timed_out"):
            status = "output_limit"
        return RunnerResult(status=status, output=rendered[:self._max_output].decode(errors="ignore"), exit_code=proc.returncode)

    @staticmethod
    def _name(container: str) -> None:
        if not re.fullmatch(r"sentinel-exec-[0-9a-f]{32}", container):
            raise ValueError("not a Sentinel-owned container name")

    def remove(self, container: str) -> bool:
        """An explicit containment acknowledgement, never a best-effort success."""
        self._name(container)
        try:
            inspected = self._command(["container", "inspect", container])
            if inspected.returncode:
                return b"No such container" in inspected.stderr or b"No such object" in inspected.stderr
            metadata = json.loads(inspected.stdout)[0]
            if metadata.get("Config", {}).get("Labels", {}).get(LABEL) != "1":
                return False
            removed = self._command(["rm", "--force", "--volumes", container])
            return removed.returncode == 0 or b"No such container" in removed.stderr or b"No such object" in removed.stderr
        except (OSError, subprocess.TimeoutExpired, ValueError, KeyError, IndexError):
            return False
