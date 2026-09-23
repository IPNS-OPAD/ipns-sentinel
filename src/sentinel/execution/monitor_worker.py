"""Internal trusted worker. Its pipe is owned by ProcessMonitor, not an agent."""
from __future__ import annotations

import hashlib
import json
import sys
import asyncio
from uuid import uuid4

from sentinel.audit import AuditLog
from sentinel.config import SentinelConfig
from sentinel.execution.monitor import MAX_FRAME
from sentinel.observer import SentinelObserver
from sentinel.state import AgentStep


def main() -> None:
    init = json.loads(sys.stdin.buffer.readline(MAX_FRAME + 1))
    cfg = SentinelConfig.model_validate(init["config"])
    observer = SentinelObserver(cfg, audit=AuditLog(cfg.audit_path, key=bytes.fromhex(init["audit_key"])), sinks=[])
    revision = hashlib.sha256(json.dumps({"config": cfg.model_dump(), "questions": [q.model_dump() for q in observer.questions]}, sort_keys=True).encode()).hexdigest()
    print(json.dumps({"revision": revision, "generation": uuid4().hex}), flush=True)
    # One event loop for the worker lifetime: enforce per-provider wall deadlines
    # without moving persistent async SDK clients between closed event loops.
    # ProcessMonitor remains the independent hard stop for a stuck worker.
    with asyncio.Runner() as loop:
        while line := sys.stdin.buffer.readline(MAX_FRAME + 1):
            if len(line) > MAX_FRAME or not line.endswith(b"\n"):
                return
            try:
                request = json.loads(line)
                if request["op"] == "receipt":
                    observer.record_result(request["agent_id"], request["result"], run_id=request["run_id"],
                                           invocation_id=request["invocation_id"], status=request["status"])
                    print(json.dumps({"recorded": True}), flush=True)
                elif request["op"] == "assess":
                    decision = loop.run(observer.aobserve(AgentStep.model_validate(request["step"])))
                    print(decision.model_dump_json(), flush=True)
                else:
                    raise ValueError("unknown operation")
            except Exception as error:
                print(json.dumps({"error": type(error).__name__}), flush=True)


if __name__ == "__main__":
    main()
