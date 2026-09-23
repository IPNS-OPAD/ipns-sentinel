"""Bounded OpenAI Responses driver; only Sentinel's local MCP tool can execute.

The normalized event stream is an operator-owned transport, not Claude Code.
Run under StreamSession for a whole-turn deadline and independent broker recovery.
"""
from __future__ import annotations

import argparse
from collections.abc import Callable
import hashlib
import json
import os
import sys
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
from uuid import uuid4

import anyio

from sentinel.credentials import load_provider_credentials, provider_environment

MODEL = "gpt-4.1-2025-04-14"
TOOL_NAME = "mcp__sentinel__run_python"
MAX_REQUEST = 32768
MAX_RESPONSE = 262144
TOOL = {"type": "function", "name": TOOL_NAME,
    "description": "Propose Python to Sentinel for approval and networkless execution. A block requires operator review; never retry.",
    "strict": True, "parameters": {"type": "object", "properties": {
        "invocation_id": {"type": "string"}, "code": {"type": "string"}},
        "required": ["invocation_id", "code"], "additionalProperties": False}}


class AgentFailure(RuntimeError):
    """Fixed categories only; never expose provider error text or credentials."""


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise AgentFailure("redirect_rejected")


class ResponsesHTTP:
    def __init__(self, key: str, *, endpoint: str = "https://api.openai.com/v1/responses") -> None:
        address = urlsplit(endpoint)
        fixture = (key == "fixture-openai-key" and address.scheme == "http" and address.hostname == "127.0.0.1"
                   and address.path == "/v1/responses" and not address.username and not address.password
                   and not address.query and not address.fragment)
        if endpoint != "https://api.openai.com/v1/responses" and not fixture:
            raise ValueError("only the official endpoint or a credential-free loopback fixture is allowed")
        self.key, self.endpoint = key, endpoint
        self.opener = build_opener(NoRedirect())

    def __call__(self, body: dict) -> dict:
        data = json.dumps(body, allow_nan=False).encode()
        if len(data) > MAX_REQUEST:
            raise AgentFailure("request_budget")
        request = Request(self.endpoint, data=data, method="POST", headers={
            "Authorization": "Bearer " + self.key, "Content-Type": "application/json"})
        try:
            with self.opener.open(request, timeout=20) as response:
                raw = response.read(MAX_RESPONSE + 1)
            if len(raw) > MAX_RESPONSE:
                raise AgentFailure("response_budget")
            result = json.loads(raw)
            if not isinstance(result, dict):
                raise AgentFailure("invalid_response")
            return result
        except HTTPError as error:
            raise AgentFailure(f"http_{error.code}") from None
        except (URLError, TimeoutError, OSError):
            raise AgentFailure("transport_error") from None
        except (ValueError, UnicodeError):
            raise AgentFailure("invalid_response") from None


class OpenAIAgent:
    """One local conversation; external HTTP and MCP are its only side-effect seams."""
    def __init__(self, *, post: Callable[[dict], dict], model: str, emit: Callable[[dict], None]) -> None:
        if model != MODEL:
            raise ValueError("this qualification adapter requires the pinned GPT-4.1 snapshot")
        self.post, self.model, self.emit = post, model, emit
        self.session_id = str(uuid4())
        self.history: list[dict] = []
        self.requests = 0
        self.turns = 0
        self.estimated_usd = 0.0
        self.stopped = False
        self.call_ids: set[str] = set()
        self.event(type="system", subtype="init", model=model, tools=[TOOL_NAME], protocol="sentinel-normalized-v1")

    def event(self, **values: Any) -> None:
        self.emit({"session_id": self.session_id, "agent_provider": "openai", **values})

    async def request(self, choice: str) -> list[dict]:
        body = {"model": self.model, "input": self.history, "tools": [TOOL], "tool_choice": choice,
                "parallel_tool_calls": False, "store": False, "max_output_tokens": 1024, "truncation": "disabled"}
        encoded = json.dumps(body, allow_nan=False).encode()
        reservation = (len(encoded) + 4096) * 2 / 1_000_000 + 1024 * 8 / 1_000_000
        if self.requests >= 8 or len(encoded) > MAX_REQUEST or self.estimated_usd + reservation > 1.0:
            raise AgentFailure("request_budget")
        self.requests += 1
        response = await anyio.to_thread.run_sync(self.post, body)
        if len(json.dumps(response).encode()) > MAX_RESPONSE:
            raise AgentFailure("response_budget")
        usage = response.get("usage") or {}
        counts = [usage.get("input_tokens"), usage.get("output_tokens")]
        if any(type(n) is not int or n < 0 for n in counts):
            raise AgentFailure("invalid_usage")
        input_tokens, output_tokens = counts
        assert isinstance(input_tokens, int) and isinstance(output_tokens, int)
        self.estimated_usd += (input_tokens * 2 + output_tokens * 8) / 1_000_000
        self.event(type="system", subtype="provider_response", response_id=response.get("id"),
            model=response.get("model"), status=response.get("status"), usage=usage,
            request_sha256=hashlib.sha256(encoded).hexdigest(), estimated_usd=self.estimated_usd)
        if response.get("model") != self.model or not isinstance(response.get("id"), str):
            raise AgentFailure("response_identity")
        if response.get("status") != "completed" or response.get("error") is not None:
            raise AgentFailure("incomplete_response")
        output = response.get("output")
        if not isinstance(output, list) or any(not isinstance(item, dict) or item.get("type") not in {"message", "function_call"} for item in output):
            raise AgentFailure("invalid_response")
        # This adapter intentionally excludes reasoning models. Only public output
        # items are retained; no hidden reasoning or credential-bearing errors.
        self.event(type="system", subtype="provider_output", response_id=response["id"], output=output)
        for item in output:
            if "status" in item and item["status"] != "completed":
                raise AgentFailure("incomplete_response")
            if item["type"] == "message":
                content = item.get("content")
                if not isinstance(content, list) or any(not isinstance(c, dict) for c in content):
                    raise AgentFailure("invalid_response")
                if any(c.get("type") == "refusal" for c in content):
                    raise AgentFailure("provider_refusal")
                if item.get("role") != "assistant" or any(c.get("type") != "output_text" or not isinstance(c.get("text"), str) for c in content):
                    raise AgentFailure("invalid_response")
        self.history.extend(output)
        return output

    async def turn(self, prompt: str, client: Any) -> None:
        try:
            if self.stopped or self.turns >= 4:
                raise AgentFailure("session_stopped")
            self.turns += 1
            inventory = (await client.list_tools()).tools
            if [t.name for t in inventory] != ["run_python"] or set(inventory[0].input_schema["properties"]) != {"invocation_id", "code"}:
                raise AgentFailure("invalid_tool_inventory")
            self.history.append({"role": "user", "content": prompt})
            self.event(type="user", message={"role": "user", "content": prompt})
            output = await self.request("auto")
            calls = [item for item in output if item["type"] == "function_call"]
            if len(calls) != 1:
                raise AgentFailure("agent_abstention" if not calls else "multiple_calls")
            call = calls[0]
            identity = call.get("call_id")
            if call.get("name") != TOOL_NAME or not isinstance(identity, str) or not identity or identity in self.call_ids:
                raise AgentFailure("invalid_tool_call")
            try:
                arguments = json.loads(call["arguments"])
            except (KeyError, TypeError, ValueError):
                raise AgentFailure("invalid_arguments") from None
            if (not isinstance(arguments, dict) or set(arguments) != {"invocation_id", "code"}
                    or not all(isinstance(v, str) and v for v in arguments.values())
                    or len(arguments["invocation_id"]) > 128 or len(arguments["code"]) > 32768):
                raise AgentFailure("invalid_arguments")
            self.call_ids.add(identity)
            self.event(type="assistant", message={"content": [{"type": "tool_use", "id": identity,
                "name": TOOL_NAME, "input": arguments}]})
            result = await client.call_tool("run_python", arguments)
            text = "".join(c.text for c in result.content if c.type == "text")
            self.event(type="user", message={"content": [{"type": "tool_result", "tool_use_id": identity,
                "is_error": result.is_error, "content": text}]})
            payload = json.loads(text)
            self.stopped = bool(result.is_error) or payload.get("status") != "succeeded"
            self.history.append({"type": "function_call_output", "call_id": identity, "output": text})
            final = await self.request("none")
            if any(item["type"] == "function_call" for item in final):
                raise AgentFailure("unexpected_followup_call")
            if not any(c["text"].strip() for item in final for c in item["content"]):
                raise AgentFailure("missing_final_report")
            for item in final:
                self.event(type="assistant", message={"content": [
                    {"type": "text", "text": c["text"]} for c in item["content"]]})
            self.event(type="result", subtype="success", is_error=False)
        except Exception as error:
            self.stopped = True
            self.event(type="result", subtype="error", is_error=True,
                       failure_category=str(error) if isinstance(error, AgentFailure) else "adapter_error")


async def serve(args: argparse.Namespace) -> None:
    from mcp import Client
    from mcp.client.stdio import StdioServerParameters
    key = load_provider_credentials(args.credentials, purpose="openai_agent")["OPENAI_API_KEY"]
    command = json.loads(args.broker_command)
    params = StdioServerParameters(command=command[0], args=command[1:], env=provider_environment({}, os.environ))
    def emit(event):
        print(json.dumps(event, allow_nan=False), flush=True)
    agent = OpenAIAgent(post=ResponsesHTTP(key, endpoint=args.endpoint), model=args.model, emit=emit)
    async with Client(params, mode="legacy", read_timeout_seconds=40) as client:
        while line := await anyio.to_thread.run_sync(lambda: sys.stdin.buffer.readline(65537)):
            if len(line) > 65536:
                raise AgentFailure("input_budget")
            message = json.loads(line)
            prompt = message["message"]["content"]
            if message.get("type") != "user" or not isinstance(prompt, str):
                raise AgentFailure("invalid_input")
            await agent.turn(prompt, client)
            if agent.stopped:
                break


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--credentials", required=True)
    parser.add_argument("--broker-command", required=True)
    parser.add_argument("--model", default=MODEL, choices=[MODEL])
    parser.add_argument("--endpoint", default="https://api.openai.com/v1/responses", help="loopback fixtures require the literal fixture key")
    args = parser.parse_args()
    try:
        anyio.run(serve, args)
    except Exception:
        print("OpenAI driver stopped; operator review required", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
