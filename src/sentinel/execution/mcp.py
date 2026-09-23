"""One agent-facing MCP tool; operator policy and execution permits stay inside."""
from __future__ import annotations

import json
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator, Callable
from typing import Any

import anyio
from mcp.server import Server, ServerRequestContext
from mcp.types import CallToolRequestParams, CallToolResult, ListToolsResult, PaginatedRequestParams, TextContent, Tool
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from sentinel.execution.broker import ExecutionBroker, ExecutionRequest, PermitRejected
from sentinel.state import ToolCall


class PythonInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    invocation_id: str = Field(min_length=1, max_length=128)
    code: str = Field(min_length=1, max_length=32768)
    peer_context: str = Field(default="", max_length=4000)


def _result(payload: dict[str, Any], *, error: bool = False) -> CallToolResult:
    return CallToolResult(is_error=error, content=[TextContent(type="text", text=json.dumps(payload))])


def create_server(broker: ExecutionBroker, *, peer_context: str | None = None,
                  peer_context_for: Callable[[str], str] | None = None) -> Server:
    """Construct a fixed-principal server; no host paths, policy or admin tool inputs."""
    if peer_context is not None and len(peer_context) > 2000:
        raise ValueError("operator peer context exceeds monitor coverage")
    if peer_context is not None and peer_context_for is not None:
        raise ValueError("choose one operator peer-context source")
    stopped = False

    @asynccontextmanager
    async def lifespan(server: Server) -> AsyncIterator[None]:
        nonlocal stopped
        try:
            yield None
        finally:
            stopped = True
            with anyio.CancelScope(shield=True):
                await anyio.to_thread.run_sync(lambda: broker.hold(operator="sentinel", reason="MCP session closed"))

    async def list_tools(ctx: ServerRequestContext, params: PaginatedRequestParams | None) -> ListToolsResult:
        schema = PythonInput.model_json_schema()
        if peer_context is not None or peer_context_for is not None:
            schema["properties"].pop("peer_context")
        return ListToolsResult(tools=[Tool(name="run_python", input_schema=schema,
            description="Run Python in a disposable, networkless container after Sentinel approval. "
                        "Use a unique invocation_id per action. Never retry a lost response with a new ID. "
                        "A block requires operator review; there is no agent resume tool.")])

    def execute(args: PythonInput) -> CallToolResult:
        context = peer_context_for(args.invocation_id) if peer_context_for is not None else peer_context
        if context is not None and len(context) > 2000:
            raise ValueError("operator peer context exceeds monitor coverage")
        request = ExecutionRequest(invocation_id=args.invocation_id,
            peer_context=args.peer_context if context is None else context,
            tool_call=ToolCall(name="python", input={"code": args.code}))
        authorization = broker.authorize(request)
        assessment = {"action": authorization.decision.action.label,
                      "reason": authorization.decision.reason[:1000],
                      "assessment_status": authorization.decision.assessment_status}
        if authorization.permit is None:
            return _result({"status": "blocked", "invocation_id": args.invocation_id,
                "decision_id": authorization.decision.decision_id, **assessment}, error=True)
        receipt = broker.execute(request, authorization.permit)
        return _result({**receipt.model_dump(), **assessment}, error=receipt.status != "succeeded")

    async def call_tool(ctx: ServerRequestContext, params: CallToolRequestParams) -> CallToolResult:
        nonlocal stopped
        if stopped:
            return _result({"status": "unavailable"}, error=True)
        if params.name != "run_python":
            return _result({"status": "invalid_request"}, error=True)
        try:
            args = PythonInput.model_validate(params.arguments or {})
        except ValidationError:
            return _result({"status": "invalid_request"}, error=True)
        if (peer_context is not None or peer_context_for is not None) and args.peer_context:
            return _result({"status": "invalid_request"}, error=True)
        # Do not abandon a running broker call on MCP cancellation. Its bounded
        # executor must finish cleanup and durable receipts before this task exits.
        try:
            return await anyio.to_thread.run_sync(execute, args, abandon_on_cancel=False)
        except PermitRejected:
            return _result({"status": "rejected", "message": "Run held or invocation already submitted; operator review required."}, error=True)
        except Exception:
            # Even an audit/transport failure must not leave the session running.
            # Never return exception messages, host paths, or permits to the model.
            stopped = True
            try:
                await anyio.to_thread.run_sync(lambda: broker.hold(operator="sentinel", reason="MCP execution failed"))
            except Exception:
                pass  # This server stays stopped even if durable storage failed.
            return _result({"status": "unavailable", "message": "Operator review required; do not retry."}, error=True)

    return Server("sentinel", lifespan=lifespan, on_list_tools=list_tools, on_call_tool=call_tool)


async def serve(broker: ExecutionBroker, peer_context: str | None = None,
                peer_context_for: Callable[[str], str] | None = None) -> None:
    from mcp.server.stdio import stdio_server

    server = create_server(broker, peer_context=peer_context, peer_context_for=peer_context_for)
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())
