"""Trajectory state: what an agent did, and what the monitor sees."""

from __future__ import annotations

import hashlib
import json
import time
from copy import deepcopy
from uuid import uuid4
from typing import Any

from pydantic import BaseModel, Field


class ToolCall(BaseModel):
    """A proposed or executed tool invocation."""

    name: str = Field(min_length=1, max_length=256)
    input: dict[str, Any] = Field(default_factory=dict)
    id: str | None = None

    def digest(self) -> str:
        """Stable hash of the call, used for transcript-integrity checks."""
        payload = json.dumps({"name": self.name, "input": self.input}, sort_keys=True, default=str)
        return hashlib.sha256(payload.encode()).hexdigest()


class AgentStep(BaseModel):
    """One observed step of one agent.

    `reasoning` is whatever legible reasoning the harness exposes: raw CoT for
    open-weight models, summarized thinking for hosted models, or the agent's
    visible plan text. Sentinel degrades to action-only monitoring when it is
    empty; it never fails open because reasoning is missing.
    """

    agent_id: str
    run_id: str = "default"
    step: int = 0
    ts: float = Field(default_factory=time.time, ge=0, allow_inf_nan=False)
    reasoning: str = ""
    proposed_tool_call: ToolCall | None = None
    tool_result: str | None = None
    peer_context: str = ""
    invocation_id: str = Field(default_factory=lambda: str(uuid4()), min_length=1)


class Trajectory(BaseModel):
    """Rolling window of steps for one agent."""

    agent_id: str
    run_id: str = "default"
    steps: list[AgentStep] = Field(default_factory=list)
    window: int = 8

    def append(self, step: AgentStep) -> None:
        self.steps.append(step)
        if len(self.steps) > self.window * 4:
            self.steps = self.steps[-self.window * 4 :]

    def recent(self) -> list[AgentStep]:
        return self.steps[-self.window :]

    def recent_actions(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for s in self.recent():
            if s.proposed_tool_call:
                out.append({"step": s.step, "invocation_id": s.invocation_id, "tool": s.proposed_tool_call.name, "input": _clip(s.proposed_tool_call.input)})
        return out

    def recent_results(self) -> list[dict[str, Any]]:
        return [{"step": s.step, "invocation_id": s.invocation_id, "result": _clip_text(s.tool_result)} for s in self.recent() if s.tool_result]


class PolicyContext(BaseModel):
    """Declared task scope, fed to the backend beside the reasoning.

    This is the plan-injection defence from PRD section 13: a benign-sounding
    rationalisation that contradicts the declared scope still scores high on
    deception because the scorer sees both.
    """

    task: str = ""
    allowed_scope: list[str] = Field(default_factory=list)
    forbidden: list[str] = Field(default_factory=list)
    allowed_hosts: list[str] = Field(default_factory=list)
    environment: str = "unspecified"


def build_monitor_state(step: AgentStep, trajectory: Trajectory, policy: PolicyContext, max_chars: int = 6000) -> dict[str, Any]:
    """Assemble the JSON object the backend scores. Text-only by design."""
    tool_input_complete = step.proposed_tool_call is None or len(json.dumps(
        step.proposed_tool_call.input, ensure_ascii=False, default=str)) <= max_chars
    return {
        "agent_id": step.agent_id,
        "policy": policy.model_dump(),
        "current_reasoning": step.reasoning[:max_chars],
        "proposed_tool_call": (
            {"name": step.proposed_tool_call.name, "input": deepcopy(step.proposed_tool_call.input) if tool_input_complete
             else {"_sentinel_unavailable": "tool input exceeds assessment budget", "digest": step.proposed_tool_call.digest()}}
            if step.proposed_tool_call
            else None
        ),
        "recent_actions": trajectory.recent_actions(),
        "recent_tool_results": trajectory.recent_results(),
        "peer_agent_context": step.peer_context[:2000],
        "coverage": {"tool_input_complete": tool_input_complete,
                     "reasoning_truncated": len(step.reasoning) > max_chars,
                     "peer_context_truncated": len(step.peer_context) > 2000},
    }


def _clip_text(s: str | None, n: int = 1500) -> str:
    if not s:
        return ""
    return s if len(s) <= n else s[:n] + f"... [+{len(s) - n} chars]"


def _clip(d: dict[str, Any], n: int = 1500) -> dict[str, Any]:
    text = json.dumps(d, ensure_ascii=False, default=str)
    return deepcopy(d) if len(text) <= n else {"_sentinel_excerpt": _clip_text(text, n), "_truncated": True}
