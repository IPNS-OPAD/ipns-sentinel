import json

from sentinel.adapters.claude_code_harness import command


def test_dedicated_profile_removes_native_tools_and_uses_only_explicit_broker():
    args = command(claude="/bin/claude", broker_command=["/bin/python", "-m", "sentinel.cli", "broker"],
                   prompt="Calculate 6 * 7", max_turns=4, budget_usd=0.5)
    def value(flag):
        return args[args.index(flag) + 1]
    assert value("--tools") == ""
    assert value("--allowedTools") == "mcp__sentinel__run_python"
    assert value("--permission-mode") == "dontAsk"
    assert "--restricted" in args and "--strict-mcp-config" in args
    assert "--disable-slash-commands" in args and "--no-session-persistence" in args
    assert "--dangerously-skip-permissions" not in args and "--bare" not in args
    assert value("--setting-sources") == ""
    assert value("--max-turns") == "4" and value("--max-budget-usd") == "0.5"
    settings = json.loads(value("--settings"))
    assert settings["disableAllHooks"] and settings["disableClaudeAiConnectors"]
    assert not settings["autoMemoryEnabled"] and settings["claudeMdExcludes"] == ["**"]
    config = json.loads(value("--mcp-config"))
    assert list(config["mcpServers"]) == ["sentinel"]
    assert config["mcpServers"]["sentinel"]["command"] == "/bin/python"


def test_stream_profile_keeps_restrictions_without_a_one_shot_prompt():
    args = command(claude="claude", broker_command=["broker"], prompt=None, model="claude-sonnet-5")
    assert args[args.index("--input-format") + 1] == "stream-json"
    assert "--replay-user-messages" in args and "--" not in args
    assert args[args.index("--tools") + 1] == ""
    assert "--restricted" in args and "--no-session-persistence" in args
    assert args[args.index("--model") + 1] == "claude-sonnet-5"
