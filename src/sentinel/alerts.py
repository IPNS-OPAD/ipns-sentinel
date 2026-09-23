"""Structured alerts (PRD section 11) and delivery sinks."""

from __future__ import annotations

import json
import sys
import time
import urllib.request
from typing import Any, Protocol

from pydantic import BaseModel, Field

from sentinel.engine import Decision
from sentinel.state import AgentStep


class Alert(BaseModel):
    agent_id: str
    run_id: str
    step: int
    ts: float = Field(default_factory=time.time)
    action: str
    severity: str
    triggers: list[dict[str, Any]]
    reasoning_excerpt: str
    proposed_tool_call: dict[str, Any] | None
    recent_actions: list[dict[str, Any]]
    policy: dict[str, Any]
    reason: str
    backend: str | None = None
    latency_ms: float | None = None
    fleet: dict[str, Any] | None = None

    @classmethod
    def from_decision(cls, step: AgentStep, decision: Decision, state: dict[str, Any], fleet: dict[str, Any] | None = None) -> "Alert":
        return cls(
            agent_id=step.agent_id, run_id=step.run_id, step=step.step, action=decision.action.label, severity=decision.severity,
            triggers=[t.model_dump() for t in decision.triggers], reasoning_excerpt=step.reasoning[:1200],
            proposed_tool_call=state.get("proposed_tool_call"), recent_actions=state.get("recent_actions", []),
            policy=state.get("policy", {}), reason=decision.reason,
            backend=decision.verdicts.backend if decision.verdicts else None,
            latency_ms=decision.verdicts.latency_ms if decision.verdicts else None, fleet=fleet,
        )


class Sink(Protocol):
    def send(self, alert: Alert) -> None: ...


class StderrSink:
    def send(self, alert: Alert) -> None:
        print(f"[sentinel] {alert.action.upper()} agent={alert.agent_id} step={alert.step} {alert.reason}", file=sys.stderr)


class JsonlSink:
    def __init__(self, path: str) -> None:
        self.path = path

    def send(self, alert: Alert) -> None:
        with open(self.path, "a") as f:
            f.write(alert.model_dump_json() + "\n")


class WebhookSink:
    """Generic JSON POST. Slack-compatible if `slack=True` (wraps in {"text": ...})."""

    def __init__(self, url: str, slack: bool = False, timeout: float = 3.0) -> None:
        self.url, self.slack, self.timeout = url, slack, timeout

    def send(self, alert: Alert) -> None:
        body: dict[str, Any] = {"text": f":rotating_light: Sentinel {alert.action.upper()} agent `{alert.agent_id}` step {alert.step}: {alert.reason}"} if self.slack else alert.model_dump()
        req = urllib.request.Request(self.url, data=json.dumps(body, default=str).encode(), headers={"Content-Type": "application/json"}, method="POST")
        try:
            urllib.request.urlopen(req, timeout=self.timeout).read()
        except Exception as e:  # alert delivery must never crash the gate
            print(f"[sentinel] webhook failed: {e}", file=sys.stderr)


def make_sink(spec: dict[str, Any]) -> Sink:
    kind = spec.get("type")
    if kind == "stderr":
        return StderrSink()
    if kind == "jsonl":
        return JsonlSink(spec["path"])
    if kind == "webhook":
        return WebhookSink(spec["url"], slack=bool(spec.get("slack", False)), timeout=float(spec.get("timeout", 3.0)))
    raise ValueError(f"unknown sink type: {kind}")
