"""Bounded, sequential user turns through one operator-owned Claude process.

No resume/relaunch or automatic retries. Tool restrictions come from the dedicated
launch profile; process cleanup is not a substitute for broker journal recovery.
"""
from __future__ import annotations

import json
import math
import os
from pathlib import Path
import selectors
import signal
import subprocess
import time
from typing import Any


class StreamFailure(RuntimeError):
    pass


class StreamSession:
    def __init__(self, argv: list[str], *, cwd: Path, env: dict[str, str], max_output_bytes: int = 2 * 1024 * 1024) -> None:
        if not 1 <= max_output_bytes <= 16 * 1024 * 1024:
            raise ValueError("invalid stream budget")
        self._proc = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True, bufsize=0)
        self.pid = self._proc.pid
        self.stdout = bytearray()
        self.stderr = bytearray()
        self._pending = bytearray()
        self._limit = max_output_bytes
        self._broken = False
        self._closed = False
        self.session_id: str | None = None
        for pipe in (self._proc.stdin, self._proc.stdout, self._proc.stderr):
            assert pipe is not None
            os.set_blocking(pipe.fileno(), False)

    @property
    def returncode(self) -> int | None:
        return self._proc.poll()

    def _retain(self, chunk: bytes, *, stderr: bool) -> None:
        buffer = self.stderr if stderr else self.stdout
        limit = min(self._limit, 65536) if stderr else self._limit
        remaining = limit - len(buffer)
        buffer.extend(chunk[:remaining])
        if len(chunk) > remaining:
            raise StreamFailure("session output budget exceeded")
        if not stderr:
            self._pending.extend(chunk)

    def turn(self, prompt: str, *, timeout_s: float) -> list[dict[str, Any]]:
        if self._broken or self._closed:
            raise StreamFailure("session is stopped; do not retry")
        if not math.isfinite(timeout_s) or not 0 < timeout_s <= 900:
            raise ValueError("invalid turn deadline")
        data = (json.dumps({"type": "user", "message": {"role": "user", "content": prompt}}) + "\n").encode()
        if len(data) > 65536:
            raise ValueError("prompt exceeds turn budget")
        deadline = time.monotonic() + timeout_s
        messages: list[dict[str, Any]] = []
        offset = 0
        assert self._proc.stdin is not None and self._proc.stdout is not None and self._proc.stderr is not None
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(self._proc.stdin, selectors.EVENT_WRITE)
                selector.register(self._proc.stdout, selectors.EVENT_READ)
                selector.register(self._proc.stderr, selectors.EVENT_READ)
                while True:
                    while b"\n" in self._pending:
                        line, _, tail = self._pending.partition(b"\n")
                        self._pending = bytearray(tail)
                        if not line.strip():
                            continue
                        message = json.loads(line)
                        if not isinstance(message, dict):
                            raise StreamFailure("invalid stream message")
                        identity = message.get("session_id")
                        if identity is not None:
                            if not isinstance(identity, str) or not identity or (self.session_id and identity != self.session_id):
                                raise StreamFailure("session identity changed")
                            self.session_id = identity
                        messages.append(message)
                        if message.get("type") == "result":
                            if offset != len(data) or not self.session_id:
                                raise StreamFailure("result without a delivered turn or session identity")
                            return messages
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise StreamFailure("turn deadline exceeded")
                    for event, _ in selector.select(remaining):
                        pipe = event.fileobj
                        if pipe is self._proc.stdin:
                            offset += os.write(event.fd, data[offset:])
                            if offset == len(data):
                                selector.unregister(pipe)
                        else:
                            chunk = os.read(event.fd, 65536)
                            if not chunk:
                                selector.unregister(pipe)
                                if pipe is self._proc.stdout:
                                    raise StreamFailure("session exited before completing its turn")
                            else:
                                self._retain(chunk, stderr=pipe is self._proc.stderr)
        except Exception as error:
            self._broken = True
            if isinstance(error, StreamFailure):
                raise
            raise StreamFailure("invalid or interrupted session stream") from None

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._proc.stdin is not None:
            self._proc.stdin.close()
        try:
            self._proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass
        # Reap this session's process group even if its leader has already exited.
        try:
            os.killpg(self.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        self._proc.wait(timeout=2)
        for pipe in (self._proc.stdout, self._proc.stderr):
            if pipe is not None:
                try:
                    while chunk := os.read(pipe.fileno(), 65536):
                        self._retain(chunk, stderr=pipe is self._proc.stderr)
                except (BlockingIOError, StreamFailure):
                    pass
                finally:
                    pipe.close()

    def __enter__(self) -> StreamSession:
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()
