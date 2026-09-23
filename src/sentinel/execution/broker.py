"""Host-owned authorization journal. Only authorize/execute belong on an agent pipe."""
from __future__ import annotations

import hashlib
import json
import math
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field

from sentinel.audit import AuditLog
from sentinel.engine import Action, Decision
from sentinel.execution.monitor import ProcessMonitor
from sentinel.state import AgentStep, ToolCall


class ExecutionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    invocation_id: str = Field(min_length=1, max_length=128)
    tool_call: ToolCall
    reasoning: str = Field(default="", max_length=16000)
    peer_context: str = Field(default="", max_length=4000)


class RunnerResult(BaseModel):
    status: Literal["succeeded", "failed", "timed_out", "cancelled", "output_limit", "unknown"]
    output: str = ""
    exit_code: int | None = None


class ExecutionReceipt(RunnerResult):
    invocation_id: str
    decision_id: str
    container: str


class Authorization(BaseModel):
    decision: Decision
    permit: str | None = None
    expires_at: float | None = None


class PermitRejected(PermissionError):
    pass


class PreparationFailed(RuntimeError):
    def __init__(self, *, container: str, removed: bool, error_type: str, interrupted: BaseException | None = None) -> None:
        super().__init__("container preparation failed; no tool code started")
        self.container, self.removed, self.error_type = container, removed, error_type
        self.interrupted = interrupted


class Runner(Protocol):
    revision: str
    def validate(self, call: ToolCall) -> None: ...
    def prepare(self, call: ToolCall) -> str: ...
    def run(self, container: str) -> RunnerResult: ...
    def remove(self, container: str) -> bool: ...


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class ExecutionBroker:
    def __init__(self, *, agent_id: str, run_id: str, path: Path, monitor: ProcessMonitor,
                 runner: Runner, audit: AuditLog, permit_ttl_s: float = 30,
                 clock: Callable[[], float] = time.time) -> None:
        if not agent_id or not run_id or audit.unsigned:
            raise ValueError("fixed identity and signed audit are required")
        if not math.isfinite(permit_ttl_s) or permit_ttl_s <= 0:
            raise ValueError("permit lifetime must be positive and finite")
        self.agent_id, self.run_id = agent_id, run_id
        self.path, self.monitor, self.runner, self.audit = Path(path), monitor, runner, audit
        self._clock, self._ttl = clock, permit_ttl_s
        self._now()
        self._run = _digest(_canonical([agent_id, run_id]))
        self._revision = _digest(_canonical([monitor.revision, runner.revision]))
        self._generation = monitor.generation
        self.path.parent.mkdir(parents=True, exist_ok=True)
        restarted = False
        with self._transaction() as db:
            db.execute("CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY, revision TEXT, state TEXT, epoch INTEGER, generation TEXT)")
            db.execute("CREATE TABLE IF NOT EXISTS permits (run TEXT, invocation TEXT, digest TEXT, decision TEXT, token TEXT, expires REAL, epoch INTEGER, status TEXT, container TEXT, receipt TEXT, PRIMARY KEY(run, invocation))")
            db.execute("INSERT OR IGNORE INTO runs VALUES (?,?,'running',0,?)", (self._run, self._revision, self._generation))
            row = db.execute("SELECT revision,generation FROM runs WHERE id=?", (self._run,)).fetchone()
            if row["revision"] != self._revision:
                raise PermitRejected("policy/executor revision changed; use a new run")
            if row["generation"] != self._generation:
                restarted = True
                db.execute("UPDATE runs SET state=CASE WHEN state='terminated' THEN state ELSE 'held' END,generation=? WHERE id=?",
                           (self._generation, self._run))
        if restarted:
            self.hold(operator="sentinel", reason="monitor restarted; review lost trajectory context and containment")

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def _running(self, db: sqlite3.Connection) -> sqlite3.Row:
        row = db.execute("SELECT * FROM runs WHERE id=?", (self._run,)).fetchone()
        if row is None or row["state"] != "running" or row["revision"] != self._revision or row["generation"] != self._generation:
            raise PermitRejected("run is held, terminated, or has a different policy")
        return row

    def _request(self, request: ExecutionRequest) -> tuple[ExecutionRequest, str]:
        payload = _canonical(request.model_dump(mode="json"))
        if len(payload.encode()) > 65536:
            raise PermitRejected("request is too large")
        snapshot = ExecutionRequest.model_validate_json(payload)
        self.runner.validate(snapshot.tool_call)
        return snapshot, _digest(payload)

    def _now(self) -> float:
        now = self._clock()
        if not math.isfinite(now) or now < 0:
            raise PermitRejected("trusted clock is invalid")
        return now

    def authorize(self, request: ExecutionRequest) -> Authorization:
        request, digest = self._request(request)
        with self._transaction() as db:
            run = self._running(db)
            try:
                db.execute("INSERT INTO permits (run,invocation,digest,epoch,status) VALUES (?,?,?,?,'assessing')",
                           (self._run, request.invocation_id, digest, run["epoch"]))
            except sqlite3.IntegrityError as error:
                raise PermitRejected("invocation was already submitted") from error
            step_number = db.execute("SELECT COUNT(*) FROM permits WHERE run=?", (self._run,)).fetchone()[0] - 1
        step = AgentStep(agent_id=self.agent_id, run_id=self.run_id, invocation_id=request.invocation_id,
                         step=step_number, ts=self._now(),
                         proposed_tool_call=request.tool_call, reasoning=request.reasoning, peer_context=request.peer_context)
        try:
            decision = self.monitor.evaluate(step)
        except Exception as error:
            decision = Decision(action=Action.PAUSE, invocation_id=request.invocation_id,
                                assessment_status="unavailable", reason="monitor unavailable; operator review required", fail_mode="closed")
            self.audit.append("assessment_unavailable", {"agent_id": self.agent_id, "run_id": self.run_id,
                "invocation_id": request.invocation_id, "decision_id": decision.decision_id,
                "error_type": type(error).__name__})
        if decision.blocks or decision.assessment_status != "complete" or decision.invocation_id != request.invocation_id:
            if not decision.blocks:
                decision = decision.model_copy(update={"action": Action.PAUSE, "reason": "assessment is incomplete or mismatched"})
            with self._transaction() as db:
                db.execute("UPDATE permits SET status='denied',decision=? WHERE run=? AND invocation=?",
                           (decision.decision_id, self._run, request.invocation_id))
            self._stop("terminated" if decision.action == Action.KILL else "held", "sentinel", decision.reason)
            return Authorization(decision=decision)
        permit = secrets.token_urlsafe(32)
        expires = self._now() + self._ttl
        with self._transaction() as db:
            current = self._running(db)
            if current["epoch"] != run["epoch"]:
                raise PermitRejected("run changed while assessing")
            self.audit.append("authorization_issued", {"agent_id": self.agent_id, "run_id": self.run_id,
                "invocation_id": request.invocation_id, "decision_id": decision.decision_id,
                "request_sha256": digest, "revision": self._revision, "expires_at": expires})
            db.execute("UPDATE permits SET status='issued',decision=?,token=?,expires=? WHERE run=? AND invocation=?",
                       (decision.decision_id, _digest(permit), expires, self._run, request.invocation_id))
        return Authorization(decision=decision, permit=permit, expires_at=expires)

    def _valid_permit(self, db: sqlite3.Connection, request: ExecutionRequest, digest: str, permit: str) -> sqlite3.Row:
        run = self._running(db)
        row = db.execute("SELECT * FROM permits WHERE run=? AND invocation=?", (self._run, request.invocation_id)).fetchone()
        if (row is None or row["status"] != "issued" or row["digest"] != digest
                or row["token"] != _digest(permit) or row["epoch"] != run["epoch"] or self._now() >= row["expires"]):
            raise PermitRejected("permit is invalid, expired, altered, or already used")
        return row

    def execute(self, request: ExecutionRequest, permit: str) -> ExecutionReceipt:
        request, digest = self._request(request)
        with self._transaction() as db:
            authorized = self._valid_permit(db, request, digest, permit)
        # Creating a stopped container runs no tool code. Register it atomically
        # with consumption before starting, so a concurrent hold can remove it.
        try:
            container = self.runner.prepare(request.tool_call)
        except BaseException as error:
            failed_container = error.container if isinstance(error, PreparationFailed) else None
            removed = error.removed if isinstance(error, PreparationFailed) else None
            if failed_container is not None and removed is False:
                with self._transaction() as db:
                    db.execute("UPDATE permits SET status='cleanup_pending',container=? WHERE run=? AND invocation=? AND status='issued'",
                               (failed_container, self._run, request.invocation_id))
            self.audit.append("execution_prepare_failed", {"agent_id": self.agent_id, "run_id": self.run_id,
                "invocation_id": request.invocation_id, "decision_id": authorized["decision"],
                "outcome": "not_started", "container": failed_container, "removed": removed,
                "error_type": error.error_type if isinstance(error, PreparationFailed) else type(error).__name__})
            self.hold(operator="sentinel", reason="container preparation failed; operator review required")
            if isinstance(error, PreparationFailed) and error.interrupted is not None:
                raise error.interrupted
            raise
        interrupted: BaseException | None = None
        try:
            with self._transaction() as db:
                row = self._valid_permit(db, request, digest, permit)
                db.execute("UPDATE permits SET status='consumed',container=? WHERE run=? AND invocation=?",
                           (container, self._run, request.invocation_id))
            self.audit.append("execution_started", {"agent_id": self.agent_id, "run_id": self.run_id,
                "invocation_id": request.invocation_id, "decision_id": row["decision"],
                "request_sha256": digest, "container": container})
            try:
                result = self.runner.run(container)
            except BaseException as error:
                if isinstance(error, Exception):
                    result = RunnerResult(status="failed")
                else:
                    result = RunnerResult(status="cancelled")
                    interrupted = error
        finally:
            try:
                removed = self.runner.remove(container)
            except Exception:
                removed = False
        if not removed:
            result.status = "unknown"
        if result.status == "unknown":
            self.hold(operator="sentinel", reason="container removal unconfirmed")
        receipt = ExecutionReceipt(**result.model_dump(), invocation_id=request.invocation_id,
                                   decision_id=row["decision"], container=container)
        with self._transaction() as db:
            current = db.execute("SELECT epoch FROM runs WHERE id=?", (self._run,)).fetchone()
            if removed and current["epoch"] != row["epoch"]:
                receipt.status = "cancelled"
            db.execute("UPDATE permits SET status=?,receipt=? WHERE run=? AND invocation=?",
                       ("finished" if removed else "consumed", receipt.model_dump_json(), self._run, request.invocation_id))
        payload = receipt.model_dump(exclude={"output"})
        payload.update(agent_id=self.agent_id, run_id=self.run_id, output_sha256=_digest(receipt.output),
                       output_bytes=len(receipt.output.encode()))
        self.audit.append("execution_receipt", payload)
        try:
            self.monitor.record_result(self.agent_id, self.run_id, request.invocation_id, receipt.output,
                "succeeded" if receipt.status == "succeeded" else "cancelled" if receipt.status == "cancelled" else "failed")
        except Exception:
            self.hold(operator="sentinel", reason="execution receipt could not reach monitor")
        if interrupted is not None:
            raise interrupted
        return receipt

    def _stop(self, state: str, operator: str, reason: str) -> bool:
        if not operator.strip() or not reason.strip():
            raise ValueError("operator identity and reason are required")
        with self._transaction() as db:
            db.execute("UPDATE runs SET state=CASE WHEN state='terminated' THEN state ELSE ? END,epoch=epoch+1 WHERE id=?", (state, self._run))
            db.execute("UPDATE permits SET status='revoked' WHERE run=? AND status IN ('issued','assessing')", (self._run,))
            containers = db.execute("SELECT invocation,container FROM permits WHERE run=? AND status IN ('consumed','cleanup_pending') AND container IS NOT NULL", (self._run,)).fetchall()
        acknowledgements = []
        for row in containers:
            try:
                removed = self.runner.remove(row["container"])
            except Exception:
                removed = False
            acknowledgements.append({"container": row["container"], "removed": removed})
            if removed:
                with self._transaction() as db:
                    db.execute("UPDATE permits SET status='cancelled' WHERE run=? AND invocation=? AND status IN ('consumed','cleanup_pending')",
                               (self._run, row["invocation"]))
        self.audit.append("run_stopped", {"agent_id": self.agent_id, "run_id": self.run_id,
            "state": state, "operator": operator, "reason": reason, "containment": acknowledgements})
        return all(a["removed"] for a in acknowledgements)

    def hold(self, *, operator: str, reason: str) -> bool:
        """Host-only: stop new work and remove registered active containers."""
        return self._stop("held", operator, reason)

    def terminate(self, *, operator: str, reason: str) -> bool:
        """Host-only: permanently stop this run (never resurrect its permits)."""
        return self._stop("terminated", operator, reason)

    def resume(self, *, operator: str, reason: str) -> None:
        """Host-only; caller must authenticate the operator outside this library."""
        if not operator.strip() or not reason.strip():
            raise ValueError("operator identity and reason are required")
        with self._transaction() as db:
            run = db.execute("SELECT state,generation FROM runs WHERE id=?", (self._run,)).fetchone()
            if run["state"] != "held" or run["generation"] != self._generation:
                raise PermitRejected("only a held run can resume; terminated runs are final")
            if db.execute("SELECT 1 FROM permits WHERE run=? AND status IN ('consumed','cleanup_pending')", (self._run,)).fetchone():
                raise PermitRejected("containment has not been acknowledged")
            self.audit.append("run_resumed", {"agent_id": self.agent_id, "run_id": self.run_id,
                "operator": operator, "reason": reason})
            db.execute("UPDATE runs SET state='running',epoch=epoch+1 WHERE id=?", (self._run,))
