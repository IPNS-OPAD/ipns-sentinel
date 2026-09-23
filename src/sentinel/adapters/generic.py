"""Generic middleware: wrap any tool executor with the pre-tool-call gate.

    guarded = guard(observer, agent_id="worker-1", executor=my_run_tool)
    result = guarded("bash", {"command": "ls"}, reasoning="list files")

Raises ToolBlocked when the decision is pause or kill. Async variant included.
"""

from __future__ import annotations

import asyncio
from copy import deepcopy
from typing import Any, Awaitable, Callable

from sentinel.engine import Decision
from sentinel.observer import SentinelObserver
from sentinel.state import AgentStep, ToolCall


class ToolBlocked(PermissionError):
    def __init__(self, decision: Decision) -> None:
        super().__init__(decision.reason)
        self.decision = decision


def guard(observer: SentinelObserver, agent_id: str, executor: Callable[[str, dict[str, Any]], Any], run_id: str = "default"):
    step_no = {"n": 0}

    def run(name: str, inp: dict[str, Any], reasoning: str = "", peer_context: str = "") -> Any:
        inp = deepcopy(inp)
        d = observer.gate(agent_id, ToolCall(name=name, input=inp), reasoning=reasoning, run_id=run_id, step=step_no["n"], peer_context=peer_context)
        step_no["n"] += 1
        if d.blocks:
            raise ToolBlocked(d)
        try:
            out = executor(name, inp)
        except BaseException as error:
            observer.record_result(agent_id, type(error).__name__, run_id=run_id, invocation_id=d.invocation_id,
                                   status="cancelled" if isinstance(error, (KeyboardInterrupt, asyncio.CancelledError)) else "failed")
            raise
        observer.record_result(agent_id, str(out), run_id=run_id, invocation_id=d.invocation_id)
        return out

    return run


def aguard(observer: SentinelObserver, agent_id: str, executor: Callable[[str, dict[str, Any]], Awaitable[Any]], run_id: str = "default"):
    step_no = {"n": 0}

    async def run(name: str, inp: dict[str, Any], reasoning: str = "", peer_context: str = "") -> Any:
        inp = deepcopy(inp)
        s = AgentStep(agent_id=agent_id, run_id=run_id, step=step_no["n"], reasoning=reasoning,
                      proposed_tool_call=ToolCall(name=name, input=inp), peer_context=peer_context)
        step_no["n"] += 1
        d = await observer.aobserve(s)
        if d.blocks:
            raise ToolBlocked(d)
        try:
            out = await executor(name, inp)
        except BaseException as error:
            observer.record_result(agent_id, type(error).__name__, run_id=run_id, invocation_id=d.invocation_id,
                                   status="cancelled" if isinstance(error, (KeyboardInterrupt, asyncio.CancelledError)) else "failed")
            raise
        observer.record_result(agent_id, str(out), run_id=run_id, invocation_id=d.invocation_id)
        return out

    return run
