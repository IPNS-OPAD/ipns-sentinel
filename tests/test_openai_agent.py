import json

import pytest

from tests.test_execution_broker import broker_parts


async def test_openai_agent_preserves_two_turns_and_uses_only_the_real_broker(broker_parts):
    pytest.importorskip("mcp")
    from mcp import Client
    from sentinel.execution.mcp import create_server
    from sentinel.adapters.openai_agent import OpenAIAgent
    broker, runner, audit, _ = broker_parts
    requests, events = [], []
    def post(body):
        requests.append(json.loads(json.dumps(body)))
        number = len(requests)
        output = [{"type": "function_call", "id": f"fc-{number}", "call_id": f"call-{number}",
                   "name": "mcp__sentinel__run_python", "arguments": json.dumps({"invocation_id": f"turn-{number}", "code": "print(42)"})}] if number % 2 else [
                   {"type": "message", "role": "assistant", "id": f"msg-{number}", "status": "completed",
                    "content": [{"type": "output_text", "text": "42", "annotations": []}]}]
        return {"id": f"resp-{number}", "model": "gpt-4.1-2025-04-14", "status": "completed", "output": output,
                "usage": {"input_tokens": 20, "output_tokens": 10}}
    async with Client(create_server(broker, peer_context="")) as client:
        agent = OpenAIAgent(post=post, model="gpt-4.1-2025-04-14", emit=events.append)
        await agent.turn("first prompt", client)
        await agent.turn("second prompt", client)
    assert runner.calls == ["print(42)"] * 2
    assert all(r["store"] is False and r["parallel_tool_calls"] is False for r in requests)
    assert [r["tool_choice"] for r in requests] == ["auto", "none", "auto", "none"]
    assert all([t["name"] for t in r["tools"]] == ["mcp__sentinel__run_python"] for r in requests)
    assert requests[2]["input"][0] == {"role": "user", "content": "first prompt"}
    assert any(i.get("type") == "function_call_output" for i in requests[2]["input"])
    assert sum(e["type"] == "result" and not e["is_error"] for e in events) == 2
    assert len({e["session_id"] for e in events}) == 1
    assert audit.verify()[0]


@pytest.mark.parametrize("repeat_call_id,blocked", [(True, False), (False, True), (False, False)])
async def test_openai_replay_or_block_cannot_execute_again(broker_parts, repeat_call_id, blocked):
    pytest.importorskip("mcp")
    from mcp import Client
    from sentinel.execution.mcp import create_server
    from sentinel.adapters.openai_agent import OpenAIAgent, MODEL, TOOL_NAME
    broker, runner, audit, _ = broker_parts
    events, requests = [], []
    def post(body):
        requests.append(body)
        number = len(requests)
        call_id = "call-1" if repeat_call_id else f"call-{number}"
        output = [{"type": "function_call", "call_id": call_id, "name": TOOL_NAME,
            "arguments": json.dumps({"invocation_id": "same-invocation", "code": "print('credential token')" if blocked else "print(42)"})}] if number % 2 else [
            {"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "Result reported"}]}]
        return {"id": f"resp-{number}", "model": MODEL, "status": "completed", "output": output,
                "usage": {"input_tokens": 20, "output_tokens": 10}}
    async with Client(create_server(broker, peer_context="")) as client:
        agent = OpenAIAgent(post=post, model=MODEL, emit=events.append)
        await agent.turn("first", client)
        await agent.turn("attempt replay", client)
        assert agent.stopped
        assert len(requests) == (2 if blocked else 3 if repeat_call_id else 4)
    assert runner.calls == ([] if blocked else ["print(42)"])
    assert audit.verify()[0]


@pytest.mark.parametrize("fault,category", [
    ("refusal", "provider_refusal"), ("empty", "agent_abstention"),
    ("multiple", "multiple_calls"), ("native", "invalid_tool_call"),
    ("arguments", "invalid_arguments"), ("incomplete", "incomplete_response"),
    ("incomplete_call", "incomplete_response"), ("incomplete_final", "incomplete_response"),
    ("model", "response_identity"), ("usage", "invalid_usage"),
    ("http", "http_503"), ("empty_final", "missing_final_report"),
    ("followup", "unexpected_followup_call"),
])
async def test_uncertain_openai_turn_stops_without_retry_or_extra_execution(broker_parts, fault, category):
    pytest.importorskip("mcp")
    from mcp import Client
    from sentinel.execution.mcp import create_server
    from sentinel.adapters.openai_agent import OpenAIAgent, AgentFailure, MODEL, TOOL_NAME
    broker, runner, audit, _ = broker_parts
    events, requests = [], []
    def post(body):
        requests.append(body)
        if fault == "http":
            raise AgentFailure("http_503")
        call = {"type": "function_call", "call_id": "call-1", "name": TOOL_NAME,
                "arguments": json.dumps({"invocation_id": "one", "code": "print(42)"})}
        response = {"id": "resp-fixture", "model": MODEL, "status": "completed", "output": [call],
                    "usage": {"input_tokens": 20, "output_tokens": 10}}
        if fault == "refusal":
            response["output"] = [{"type": "message", "role": "assistant", "content": [{"type": "refusal", "refusal": "Declined"}]}]
        elif fault == "empty" or (fault == "empty_final" and len(requests) == 2):
            response["output"] = []
        elif fault == "multiple":
            response["output"].append({**call, "call_id": "call-2"})
        elif fault == "native":
            call["name"] = "shell"
        elif fault == "arguments":
            call["arguments"] = '{"code":"print(42)","invocation_id":"one","peer_context":"forged"}'
        elif fault == "incomplete":
            response["status"] = "incomplete"
        elif fault == "incomplete_call":
            call["status"] = "incomplete"
        elif fault == "incomplete_final" and len(requests) == 2:
            response["output"] = [{"type": "message", "role": "assistant", "status": "incomplete",
                                   "content": [{"type": "output_text", "text": "42"}]}]
        elif fault == "model":
            response["model"] = "unexpected-model"
        elif fault == "usage":
            response["usage"] = {}
        return response
    async with Client(create_server(broker, peer_context="")) as client:
        agent = OpenAIAgent(post=post, model=MODEL, emit=events.append)
        await agent.turn("one", client)
        assert events[-1]["failure_category"] == category
        assert events[-1]["is_error"]
        count = len(requests)
        await agent.turn("do not retry", client)
        assert len(requests) == count
    assert runner.calls == (["print(42)"] if fault in {"empty_final", "followup", "incomplete_final"} else [])
    assert audit.verify()[0]
