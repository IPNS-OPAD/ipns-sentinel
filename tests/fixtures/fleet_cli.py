"""External Claude transport fixture; real MCP, monitor and broker, no Docker/API."""
import ast
import json
import os
from pathlib import Path
import re
import sys

import anyio
from mcp import Client

from sentinel.audit import AuditLog
from sentinel.config import SentinelConfig
from sentinel.execution.broker import ExecutionBroker, RunnerResult
from sentinel.execution.mcp import create_server
from sentinel.execution.monitor import ProcessMonitor
from sentinel.execution.turns import load_turn_context
from tests.test_execution_broker import ContainerFixture


async def main():
    args = json.loads(sys.argv[sys.argv.index("--mcp-config") + 1])["mcpServers"]["sentinel"]["args"]
    def option(name):
        return args[args.index(name) + 1]
    directory = Path(option("--state-dir"))
    cfg = SentinelConfig.load(option("--config"))
    key = Path(os.environ["SENTINEL_AUDIT_KEY_FILE"]).read_bytes()
    agent, run_id = option("--agent-id"), option("--run-id")
    class RunnerFixture(ContainerFixture):
        def run(self, container):
            code = self.containers[container]
            output = "{'actual': 99, 'validated': True}\n" if "'validated'" in code else "42\n"
            if fixture_fault == "wrong_output":
                output = "99\n"
            return RunnerResult(status="failed" if fixture_fault == "failed_execution" else "succeeded",
                                output=output, exit_code=1 if fixture_fault == "failed_execution" else 0)
    def emit(message):
        print(json.dumps({"session_id": "fixture-session", **message}), flush=True)
    with ProcessMonitor(cfg, audit_key=key, credentials={}) as monitor:
        broker = ExecutionBroker(agent_id=agent, run_id=run_id, path=directory / "execution.db", monitor=monitor,
                                 runner=RunnerFixture(), audit=AuditLog(directory / "execution.jsonl", key=key))
        server = create_server(broker, peer_context_for=lambda invocation: load_turn_context(
            Path(option("--turn-context-dir")), agent_id=agent, run_id=run_id, invocation_id=invocation))
        async with Client(server) as client:
            emit({"type": "system", "subtype": "init", "tools": ["mcp__sentinel__run_python"], "model": "fixture"})
            for line in sys.stdin:
                user = json.loads(line)
                emit(user)
                match = re.search(r"with invocation_id=(.+?) and code=(.+?)\. Only supply", user["message"]["content"])
                invocation, code = (ast.literal_eval(value) for value in match.groups())
                if fixture_fault == "changed_attack":
                    code = "print('credential token')"
                inputs = {"invocation_id": invocation, "code": code}
                emit({"type": "assistant", "message": {"content": [
                    {"type": "tool_use", "id": "use-1", "name": "mcp__sentinel__run_python", "input": inputs}]}})
                response = await client.call_tool("run_python", inputs)
                result = {"type": "tool_result",
                    "tool_use_id": "wrong" if fixture_fault == "wrong_result_id" else "use-1",
                    "is_error": response.is_error, "content": response.content[0].text}
                if fixture_fault == "missing_error_flag":
                    result.pop("is_error")
                emit({"type": "user", "message": {"content": [result]}})
                emit({"type": "result", "subtype": "success", "is_error": False})


if __name__ == "__main__":
    anyio.run(main)
