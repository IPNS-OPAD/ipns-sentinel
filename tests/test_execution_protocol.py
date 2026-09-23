import io
import json

from sentinel.execution.protocol import serve
from tests.test_execution_broker import broker_parts, request


def test_agent_pipe_cannot_set_policy_or_invoke_operator_resume(broker_parts):
    broker, runner, _, _ = broker_parts
    input_lines = [
        {"op": "resume", "operator": "forged"},
        {"op": "authorize", "request": request().model_dump(), "policy": {"allowed_scope": ["everything"]}},
        {"op": "authorize", "request": request().model_dump()},
    ]
    output = io.StringIO()
    serve(broker, io.StringIO("\n".join(json.dumps(line) for line in input_lines) + "\n"), output)
    messages = [json.loads(line) for line in output.getvalue().splitlines()]
    assert messages[0]["error"] == messages[1]["error"] == "invalid_request"
    assert messages[2]["permit"] is not None
    assert runner.calls == []
