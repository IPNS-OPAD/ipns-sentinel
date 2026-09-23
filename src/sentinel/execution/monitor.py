"""A bounded JSON pipe to a trusted monitor process; never pickle agent input."""
from __future__ import annotations

import json
import math
import os
import selectors
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Mapping
from typing import Any, Literal

from sentinel.config import SentinelConfig
from sentinel.credentials import provider_environment
from sentinel.engine import Decision
from sentinel.state import AgentStep

MAX_FRAME = 1024 * 1024


class MonitorUnavailable(RuntimeError):
    pass


class ProcessMonitor:
    def __init__(self, config: SentinelConfig, *, audit_key: bytes, timeout_s: float = 5.0,
                 credentials: Mapping[str, str] | None = None,
                 environment: Mapping[str, str] | None = None) -> None:
        cfg = SentinelConfig.model_validate(config.model_dump())
        if cfg.on_backend_error != "closed" or cfg.on_backend_refusal == "open":
            raise ValueError("execution requires closed error/refusal handling")
        if len(audit_key) < 32 or not math.isfinite(timeout_s) or timeout_s <= 0:
            raise ValueError("use a 32-byte audit key and a positive finite deadline")
        secondary = cfg.backend.secondary()
        if secondary and cfg.backend.timeout + secondary.timeout + 0.5 > timeout_s:
            raise ValueError("fallback budget must fit inside monitor deadline with at least 0.5s framing/audit margin")
        self.timeout_s = timeout_s
        self._lock = threading.Lock()
        # Trusted caller can opt out of all ambient routing/auth/proxy settings.
        parent = os.environ if environment is None else environment
        worker_env = dict(parent) if credentials is None else provider_environment(credentials, parent)
        self._proc = subprocess.Popen(
            [sys.executable, "-I", "-m", "sentinel.execution.monitor_worker"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            start_new_session=True, close_fds=True,
            env=worker_env)
        self.pid = self._proc.pid
        try:
            ready = self._exchange({"config": cfg.model_dump(), "audit_key": audit_key.hex()})
            self.revision: str = ready["revision"]
            self.generation: str = ready["generation"]
        except BaseException:
            self.close()
            raise

    def _exchange(self, message: dict[str, Any]) -> dict[str, Any]:
        deadline = time.monotonic() + self.timeout_s
        if not self._lock.acquire(timeout=self.timeout_s):
            raise MonitorUnavailable("monitor queue deadline exceeded")
        try:
            if self._proc.poll() is not None:
                raise MonitorUnavailable("monitor process is not running")
            data = json.dumps(message, allow_nan=False).encode() + b"\n"
            if len(data) > MAX_FRAME:
                raise ValueError("monitor frame too large")
            assert self._proc.stdin is not None and self._proc.stdout is not None
            # Nonblocking writes are included in the same whole-exchange deadline.
            os.set_blocking(self._proc.stdin.fileno(), False)
            out = bytearray()
            with selectors.DefaultSelector() as selector:
                selector.register(self._proc.stdin, selectors.EVENT_WRITE)
                selector.register(self._proc.stdout, selectors.EVENT_READ)
                offset = 0
                while b"\n" not in out:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise MonitorUnavailable("monitor deadline exceeded")
                    for event, _ in selector.select(remaining):
                        if event.fileobj is self._proc.stdin:
                            offset += os.write(self._proc.stdin.fileno(), data[offset:])
                            if offset == len(data):
                                selector.unregister(self._proc.stdin)
                        else:
                            part = os.read(self._proc.stdout.fileno(), 65536)
                            if not part:
                                raise MonitorUnavailable("monitor exited without a response")
                            out.extend(part)
                            if len(out) > MAX_FRAME:
                                raise MonitorUnavailable("monitor response too large")
            result = json.loads(out)
            if not isinstance(result, dict) or "error" in result:
                raise MonitorUnavailable("monitor rejected the request")
            return result
        except Exception as error:
            self.close()
            if isinstance(error, MonitorUnavailable):
                raise
            raise MonitorUnavailable(type(error).__name__) from error
        finally:
            self._lock.release()

    def evaluate(self, step: AgentStep) -> Decision:
        return Decision.model_validate(self._exchange({"op": "assess", "step": step.model_dump()}))

    def record_result(self, agent_id: str, run_id: str, invocation_id: str, result: str,
                      status: Literal["succeeded", "failed", "cancelled"]) -> None:
        self._exchange({"op": "receipt", "agent_id": agent_id, "run_id": run_id,
                        "invocation_id": invocation_id, "result": result, "status": status})

    def close(self) -> None:
        if self._proc.poll() is None:
            try:
                os.killpg(self.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        self._proc.wait(timeout=2)
        for stream in (self._proc.stdin, self._proc.stdout):
            if stream is not None:
                stream.close()

    def __enter__(self) -> "ProcessMonitor":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()
