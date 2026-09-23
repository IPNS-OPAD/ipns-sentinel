"""Claude Code hook adapter (PreToolUse gate + PostToolUse integrity record).

settings.json:
    {"hooks": {"PreToolUse": [{"matcher": "Bash|Write|Edit|MultiEdit|WebFetch",
        "hooks": [{"type": "command", "command": "sentinel hook pre", "timeout": 10}]}],
               "PostToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "sentinel hook post", "timeout": 5}]}]}}

Each hook is a fresh process: recent actions are rebuilt from the transcript
tail, and fleet + per-session history live in the sqlite path from config.
Action mapping: allow/log -> no decision (normal permission flow); warn ->
additionalContext; pause -> "ask"; kill -> "deny".

Failure policy: any exception inside the gate exits 2 (hard block) when
`on_backend_error: closed`, else exits 1 (non-blocking, visible error).
Nothing fails open silently.
"""

from __future__ import annotations

import hashlib
import json
import sys
from typing import Any

from sentinel.config import SentinelConfig
from sentinel.engine import Action
from sentinel.observer import SentinelObserver
from sentinel.state import AgentStep, ToolCall


def _tail_lines(path: str, max_bytes: int = 400_000) -> list[str]:
    try:
        with open(path, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - max_bytes))
            data = f.read().decode("utf-8", "replace")
    except OSError:
        return []
    lines = data.splitlines()
    return lines[1:] if len(lines) > 1 and size > max_bytes else lines


def parse_transcript(path: str, tool_use_id: str | None, k: int = 8) -> tuple[str, list[ToolCall]]:
    """Return (reasoning text of the latest assistant message, last K tool calls).

    Claude Code may split one assistant message across several JSONL entries
    that share `message.id`; text is accumulated per message id and reset when
    the id changes, so a tool-only message yields empty reasoning (action-only
    mode) rather than inheriting an earlier turn's plan.
    """
    reasoning_parts: list[str] = []
    calls: list[ToolCall] = []
    last_id: str | None = None
    for line in _tail_lines(path):
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(rec, dict) or rec.get("type") != "assistant":
            continue
        msg = rec.get("message") or {}
        if not isinstance(msg, dict):
            continue
        mid = msg.get("id") or rec.get("uuid")
        if mid != last_id:
            reasoning_parts = []
            last_id = mid
        content = msg.get("content") or []
        if not isinstance(content, list):
            continue
        for b in content:
            if not isinstance(b, dict):
                continue
            t = b.get("type")
            if t in ("text", "thinking"):
                s = b.get("text") or b.get("thinking") or ""
                if s:
                    reasoning_parts.append(s)
            elif t == "tool_use":
                if tool_use_id and b.get("id") == tool_use_id:
                    continue  # the call being gated arrives on stdin
                inp = b.get("input")
                calls.append(ToolCall(name=str(b.get("name", "?")), input=inp if isinstance(inp, dict) else {}, id=b.get("id")))
    return "\n".join(reasoning_parts), calls[-k:]


def handle_pre(payload: dict[str, Any], cfg: SentinelConfig | None = None) -> dict[str, Any] | None:
    cfg = cfg or SentinelConfig.load()
    obs = SentinelObserver(cfg)
    agent_id = payload.get("agent_id") or payload.get("session_id") or "claude-code"
    run_id = payload.get("session_id") or "default"
    ti = payload.get("tool_input")
    tc = ToolCall(name=str(payload.get("tool_name", "?")), input=ti if isinstance(ti, dict) else {}, id=payload.get("tool_use_id"))
    reasoning = ""
    recent: list[ToolCall] = []
    if payload.get("transcript_path"):
        reasoning, recent = parse_transcript(payload["transcript_path"], tc.id, k=cfg.trajectory_window)
    traj = obs._trajectory(agent_id, run_id)
    for i, c in enumerate(recent):
        traj.append(AgentStep(agent_id=agent_id, run_id=run_id, step=i, proposed_tool_call=c))
    d = obs.gate(agent_id, tc, reasoning=reasoning, run_id=run_id, step=len(recent))
    if d.action == Action.KILL:
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                       "permissionDecisionReason": f"Sentinel blocked this call: {d.reason}"}}
    if d.action == Action.PAUSE:
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask",
                                       "permissionDecisionReason": f"Sentinel paused this call for review: {d.reason}"}}
    if d.action == Action.WARN:
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                       "additionalContext": f"Sentinel warning: {d.reason}. Stay within the declared task scope."}}
    return None


def handle_post(payload: dict[str, Any], cfg: SentinelConfig | None = None) -> None:
    """Transcript-integrity record (hook point 4): what actually ran, signed, outside the agent's reach."""
    cfg = cfg or SentinelConfig.load()
    obs = SentinelObserver(cfg)
    ti = payload.get("tool_input")
    tc = ToolCall(name=str(payload.get("tool_name", "?")), input=ti if isinstance(ti, dict) else {}, id=payload.get("tool_use_id"))
    resp = payload.get("tool_response")
    resp_s = json.dumps(resp, sort_keys=True, default=str) if resp is not None else ""
    obs.audit.append("tool_executed", {
        "agent_id": payload.get("agent_id") or payload.get("session_id"), "run_id": payload.get("session_id"),
        "tool_use_id": tc.id, "tool": tc.name, "input_digest": tc.digest(),
        "response_sha256": hashlib.sha256(resp_s.encode()).hexdigest(), "response_bytes": len(resp_s),
    })


def _closed() -> bool:
    try:
        return SentinelConfig.load().on_backend_error == "closed"
    except Exception:
        return True  # unreadable config: treat as closed


def main_pre() -> int:
    try:
        payload = json.load(sys.stdin)
        out = handle_pre(payload)
    except Exception as e:
        closed = _closed()
        print(f"[sentinel] hook error ({'blocking' if closed else 'non-blocking'}): {e}", file=sys.stderr)
        return 2 if closed else 1
    if out:
        print(json.dumps(out))
    return 0


def main_post() -> int:
    try:
        payload = json.load(sys.stdin)
        handle_post(payload)
    except Exception as e:
        print(f"[sentinel] hook error: {e}", file=sys.stderr)
        return 2 if _closed() else 1
    return 0
