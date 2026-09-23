"""Dedicated local Claude Code profile, separate from the legacy hook adapter.

The trusted host still owns Claude Code, MCP and Docker. CLI tool restrictions
are not OS isolation of the harness process or a defence against managed hooks.
"""
from __future__ import annotations

import json
import math


def command(*, claude: str, broker_command: list[str], prompt: str | None,
            max_turns: int = 4, budget_usd: float = 0.5, model: str | None = None) -> list[str]:
    """Operator launch profile; caller must provide an empty working directory."""
    if not broker_command or not 1 <= max_turns <= 20 or not math.isfinite(budget_usd) or budget_usd <= 0:
        raise ValueError("a broker command and bounded positive budget/turn limit are required")
    settings = {"disableAllHooks": True, "disableClaudeAiConnectors": True,
                "autoMemoryEnabled": False, "claudeMdExcludes": ["**"]}
    config = {"mcpServers": {"sentinel": {"type": "stdio", "command": broker_command[0],
                                        "args": broker_command[1:]}}}
    args = [claude, "--print", "--restricted", "--tools", "", "--strict-mcp-config",
            "--mcp-config", json.dumps(config), "--setting-sources", "",
            "--settings", json.dumps(settings), "--disable-slash-commands", "--no-chrome",
            "--permission-mode", "dontAsk", "--permission-prompts", "none",
            "--allowedTools", "mcp__sentinel__run_python", "--no-session-persistence",
            "--max-turns", str(max_turns), "--max-budget-usd", str(budget_usd),
            "--output-format", "stream-json", "--verbose"]
    if model is not None:
        args += ["--model", model]
    return args + (["--input-format", "stream-json", "--replay-user-messages"] if prompt is None else ["--", prompt])
