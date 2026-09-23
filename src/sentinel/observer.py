"""SentinelObserver: the orchestrator (PRD section 7).

    step -> prefilter -> backend (typed questions) -> engine -> correlation -> audit + alerts

`observe()` is the post-step observer; `gate()` is the pre-tool-call gate.
Both return a Decision. The caller maps the action onto its harness.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sys
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable, Literal

from sentinel.alerts import Alert, Sink, make_sink
from sentinel.audit import AuditLog
from sentinel.backends import make_backend
from sentinel.backends.base import Backend, BackendError, BackendInvalidResponse, BackendRefusal, Verdicts, validate_verdicts, failure_metadata
from sentinel.config import SentinelConfig
from sentinel.correlation import Correlator, DecisionStore, FleetSignal
from sentinel.engine import Action, Decision, DecisionEngine
from sentinel.prefilter import Prefilter
from sentinel.questions import QuestionSpec, load_from_yaml, select
from sentinel.state import AgentStep, PolicyContext, ToolCall, Trajectory, build_monitor_state

_ACTION_BY_NAME = {a.label: a for a in Action}


@dataclass
class _Assessment:
    status: str
    verdicts: Verdicts | None = None
    attempts: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def exhausted(cls, attempts: list[dict[str, Any]]) -> "_Assessment":
        statuses = {attempt["status"] for attempt in attempts}
        status = "refused" if "refused" in statuses else "incomplete" if "incomplete" in statuses else "unavailable"
        return cls(status, attempts=attempts)


def _failure_status(error: Exception) -> str:
    if isinstance(error, BackendRefusal):
        return "refused"
    if isinstance(error, BackendInvalidResponse) or not isinstance(error, (BackendError, TimeoutError)):
        return "incomplete"
    return "unavailable"


class SentinelObserver:
    def __init__(self, config: SentinelConfig | None = None, backend: Backend | None = None, fallback: Backend | None = None,
                 audit: AuditLog | None = None, sinks: list[Sink] | None = None, correlator: Correlator | None = None) -> None:
        self.cfg = SentinelConfig.model_validate(config.model_dump()) if config else SentinelConfig()
        self._backend = backend
        self._fallback = fallback
        self._secondary = self.cfg.backend.secondary()
        self.questions: list[QuestionSpec] = load_from_yaml(self.cfg.question_bank) if self.cfg.question_bank else select(self.cfg.questions)
        if not self.questions or len({q.name for q in self.questions}) != len(self.questions):
            raise ValueError("question bank must contain unique, nonempty questions")
        self._config_digest = hashlib.sha256(self.cfg.model_dump_json().encode()).hexdigest()
        self._question_digest = hashlib.sha256(json.dumps([q.model_dump() for q in self.questions], sort_keys=True).encode()).hexdigest()
        self.prefilter = Prefilter()
        self.engine = DecisionEngine(self.cfg.thresholds, on_backend_error=self.cfg.on_backend_error, on_backend_refusal=self.cfg.on_backend_refusal)
        self.audit = audit or AuditLog(os.path.expanduser(self.cfg.audit_path))
        if self.cfg.profile == "production" and self.audit.unsigned:
            raise ValueError("production profile requires a signed audit")
        self.sinks: list[Sink] = sinks if sinks is not None else [make_sink(s) for s in self.cfg.alert_sinks]
        cc = self.cfg.correlation
        self.correlator: Correlator | None = correlator if correlator is not None else (
            Correlator(cc.rising_threshold, cc.min_agents, cc.window_s, os.path.expanduser(cc.path) if cc.path else None,
                       max_future_skew_s=cc.max_future_skew_s) if cc.enabled else None)
        self.store: DecisionStore | None = DecisionStore(os.path.expanduser(cc.path)) if cc.path else None
        self.policy: PolicyContext = self.cfg.policy
        self._traj: dict[tuple[str, str], Trajectory] = {}
        self._history: dict[tuple[str, str], list[Decision]] = defaultdict(list)
        self._pending: dict[tuple[str, str, str], tuple[AgentStep, Decision]] = {}
        self._inflight: set[tuple[str, str, str]] = set()
        self._invocation_lock = threading.Lock()
        self._min_alert = _ACTION_BY_NAME[self.cfg.min_action_to_alert]

    # --- public API ----------------------------------------------------------
    @property
    def backend(self) -> Backend:
        if self._backend is None:
            self._backend = make_backend(self.cfg.backend.kind, **self.cfg.backend.primary_kwargs())
        return self._backend

    @property
    def fallback(self) -> Backend | None:
        if self._fallback is None and self._secondary:
            self._fallback = make_backend(self._secondary.kind, **self._secondary.model_dump(exclude={"kind"}, exclude_none=True))
        return self._fallback

    def gate(self, agent_id: str, tool_call: ToolCall, reasoning: str = "", run_id: str = "default", step: int | None = None,
             peer_context: str = "") -> Decision:
        """Pre-tool-call gate. Blocks when decision.blocks is True."""
        traj = self._trajectory(agent_id, run_id)
        s = AgentStep(agent_id=agent_id, run_id=run_id, step=step if step is not None else len(traj.steps),
                      reasoning=reasoning, proposed_tool_call=tool_call, peer_context=peer_context)
        return self.observe(s)

    def observe(self, step: AgentStep) -> Decision:
        return self._run(step, self._evaluate_sync)

    async def aobserve(self, step: AgentStep) -> Decision:
        return await self._arun(step)

    def record_result(self, agent_id: str, tool_result: str, run_id: str = "default", *,
                      invocation_id: str | None = None,
                      status: Literal["succeeded", "failed", "cancelled"] = "succeeded") -> None:
        """Attach a receipt to its authorized invocation; never guess among concurrent calls."""
        if invocation_id is None:
            candidates = [key for key in self._pending if key[:2] == (agent_id, run_id)]
            if len(candidates) != 1:
                raise ValueError("invocation_id is required unless exactly one invocation is pending")
            invocation_id = candidates[0][2]
        key = (agent_id, run_id, invocation_id)
        if key not in self._pending:
            raise ValueError("unknown or completed invocation")
        step, decision = self._pending[key]
        kind = {"succeeded": "tool_executed", "failed": "tool_failed", "cancelled": "tool_cancelled"}[status]
        self.audit.append(kind, {
            "agent_id": agent_id, "run_id": run_id, "invocation_id": invocation_id,
            "decision_id": decision.decision_id, "status": status,
            "tool_use_id": step.proposed_tool_call.id if step.proposed_tool_call else None,
            "tool_call_digest": step.proposed_tool_call.digest() if step.proposed_tool_call else None,
            "response_sha256": hashlib.sha256(tool_result.encode()).hexdigest(),
            "response_bytes": len(tool_result.encode()),
        })
        step.tool_result = tool_result[:4000]
        del self._pending[key]

    # --- internals -----------------------------------------------------------
    def _trajectory(self, agent_id: str, run_id: str) -> Trajectory:
        key = (agent_id, run_id)
        if key not in self._traj:
            self._traj[key] = Trajectory(agent_id=agent_id, run_id=run_id, window=self.cfg.trajectory_window)
        return self._traj[key]

    def _assessment_sources(self) -> list[tuple[str, str, Callable[[], Backend | None], float]]:
        sources: list[tuple[str, str, Callable[[], Backend | None], float]] = [
            ("primary", self.cfg.backend.kind, lambda: self.backend, self.cfg.backend.timeout)]
        if self._fallback is not None or self._secondary is not None:
            name = self._secondary.kind if self._secondary else "injected"
            timeout = self._secondary.timeout if self._secondary else self.cfg.backend.timeout
            sources.append(("fallback", name, lambda: self.fallback, timeout))
        return sources

    def _evaluate_sync(self, state: dict[str, Any]) -> _Assessment:
        attempts: list[dict[str, Any]] = []
        for role, name, get_backend, _ in self._assessment_sources():
            attempt: dict[str, Any] = {"role": role, "backend": name}
            started = time.monotonic()
            try:
                backend = get_backend()
                assert backend is not None
                attempt["backend"] = backend.name
                verdicts = validate_verdicts(backend.evaluate(state, self.questions), self.questions)
                attempt.update(status="complete", model=verdicts.model)
                return _Assessment("complete", verdicts, attempts)
            except Exception as error:
                attempt.update(status=_failure_status(error), error_type=type(error).__name__, **failure_metadata(error))
                print(f"[sentinel] {role} {attempt['status']}: {type(error).__name__}", file=sys.stderr)
            finally:
                attempt["elapsed_ms"] = round((time.monotonic() - started) * 1000, 3)
                attempts.append(attempt)
        return _Assessment.exhausted(attempts)

    async def _evaluate_async(self, state: dict[str, Any]) -> _Assessment:
        attempts: list[dict[str, Any]] = []
        for role, name, get_backend, timeout in self._assessment_sources():
            attempt: dict[str, Any] = {"role": role, "backend": name}
            started = time.monotonic()
            try:
                backend = get_backend()
                assert backend is not None
                attempt["backend"] = backend.name
                answers = await asyncio.wait_for(backend.aevaluate(state, self.questions), timeout)
                verdicts = validate_verdicts(answers, self.questions)
                attempt.update(status="complete", model=verdicts.model)
                return _Assessment("complete", verdicts, attempts)
            except Exception as error:
                attempt.update(status=_failure_status(error), error_type=type(error).__name__, **failure_metadata(error))
                print(f"[sentinel] {role} {attempt['status']}: {type(error).__name__}", file=sys.stderr)
            finally:
                attempt["elapsed_ms"] = round((time.monotonic() - started) * 1000, 3)
                attempts.append(attempt)
        return _Assessment.exhausted(attempts)

    def _run(self, step: AgentStep, evaluate: Callable[[dict[str, Any]], _Assessment]) -> Decision:
        step = step.model_copy(deep=True)
        traj = self._trajectory(step.agent_id, step.run_id)
        self._reserve_invocation(step, traj)
        try:
            traj.append(step)
            state = build_monitor_state(step, traj, self.policy, self.cfg.state_max_chars)
            hits = self.prefilter.run(step, self.policy)
            if any(hit.on == "block" for hit in hits):
                assessment = _Assessment("not_requested")
            elif not state["coverage"]["tool_input_complete"]:
                assessment = _Assessment("incomplete_input")
            else:
                assessment = evaluate(state)
            return self._finish(step, traj, state, hits, assessment)
        finally:
            self._release_invocation(step)

    async def _arun(self, step: AgentStep) -> Decision:
        step = step.model_copy(deep=True)
        traj = self._trajectory(step.agent_id, step.run_id)
        self._reserve_invocation(step, traj)
        try:
            traj.append(step)
            state = build_monitor_state(step, traj, self.policy, self.cfg.state_max_chars)
            hits = self.prefilter.run(step, self.policy)
            if any(hit.on == "block" for hit in hits):
                assessment = _Assessment("not_requested")
            elif not state["coverage"]["tool_input_complete"]:
                assessment = _Assessment("incomplete_input")
            else:
                assessment = await self._evaluate_async(state)
            return self._finish(step, traj, state, hits, assessment)
        finally:
            self._release_invocation(step)

    def _reserve_invocation(self, step: AgentStep, trajectory: Trajectory) -> None:
        key = (step.agent_id, step.run_id, step.invocation_id)
        with self._invocation_lock:
            if key in self._inflight or key in self._pending or any(previous.invocation_id == step.invocation_id for previous in trajectory.steps):
                raise ValueError("duplicate invocation_id")
            self._inflight.add(key)

    def _release_invocation(self, step: AgentStep) -> None:
        with self._invocation_lock:
            self._inflight.discard((step.agent_id, step.run_id, step.invocation_id))

    def _finish(self, step: AgentStep, traj: Trajectory, state: dict[str, Any], hits, assessment: _Assessment) -> Decision:
        verdicts = assessment.verdicts
        key = (step.agent_id, step.run_id)
        fleet: FleetSignal | None = None
        boost = 0
        if self.correlator is not None:
            score = Correlator.coordination_score(verdicts, [h.rule_id for h in hits])
            fleet = self.correlator.record(step.agent_id, score, step.ts)
            boost = fleet.boost
        history = self._history[key]
        if self.store is not None:
            history = [Decision(action=Action(a), own_signal=o) for a, o in self.store.recent(step.agent_id, step.run_id, self.cfg.thresholds.window_steps)]
        decision = self.engine.score(verdicts, self.questions, hits, history, correlation_boost=boost,
                                     backend_failed=assessment.status in ("unavailable", "incomplete"),
                                     backend_refused=assessment.status == "refused", input_incomplete=not state["coverage"]["tool_input_complete"])
        decision.assessment_status = assessment.status
        decision.invocation_id = step.invocation_id
        decision.fleet_boost = boost
        self._history[key].append(decision)
        self._history[key] = self._history[key][-self.cfg.thresholds.window_steps:]
        if self.store is not None:
            self.store.add(step.agent_id, step.run_id, step.ts, int(decision.action), decision.own_signal)
        if fleet and fleet.boost:
            decision.reason += f" [{fleet.note}]"

        self.audit.append("decision", {
            "agent_id": step.agent_id, "run_id": step.run_id, "step": step.step, "action": decision.action.label,
            "observed_ts": step.ts, "peer_context_sha256": hashlib.sha256(step.peer_context.encode()).hexdigest(),
            "invocation_id": step.invocation_id, "decision_id": decision.decision_id,
            "tool_use_id": step.proposed_tool_call.id if step.proposed_tool_call else None,
            "severity": decision.severity, "reason": decision.reason, "fail_mode": decision.fail_mode,
            "assessment_status": decision.assessment_status,
            "assessment_attempts": assessment.attempts,
            "coverage": state["coverage"],
            "config_sha256": self._config_digest, "questions_sha256": self._question_digest,
            "policy_sha256": hashlib.sha256(self.policy.model_dump_json().encode()).hexdigest(),
            "triggers": [t.model_dump() for t in decision.triggers],
            "tool": step.proposed_tool_call.name if step.proposed_tool_call else None,
            "tool_call": state.get("proposed_tool_call") if self.cfg.audit_raw_inputs else None,
            "tool_call_digest": step.proposed_tool_call.digest() if step.proposed_tool_call else None,
            "reasoning_sha256": hashlib.sha256(step.reasoning.encode()).hexdigest(),
            "backend": verdicts.backend if verdicts else None, "latency_ms": verdicts.latency_ms if verdicts else None,
            "model": verdicts.model if verdicts else None,
            "fleet": fleet.model_dump() if fleet else None,
        })
        if step.proposed_tool_call and step.tool_result is None and not decision.blocks:
            self._pending[(step.agent_id, step.run_id, step.invocation_id)] = (step, decision.model_copy(deep=True))
        if decision.action >= self._min_alert:
            alert = Alert.from_decision(step, decision, state, fleet.model_dump() if fleet else None)
            for sink in self.sinks:
                try:
                    sink.send(alert)
                except Exception as e:  # never let a sink break the gate
                    print(f"[sentinel] sink failed: {e}", file=sys.stderr)
        return decision
