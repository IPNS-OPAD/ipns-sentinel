from sentinel.backends.fake import FakeBackend
from sentinel.observer import SentinelObserver
from sentinel.state import AgentStep, PolicyContext, ToolCall, Trajectory, build_monitor_state


def test_current_tool_arguments_are_not_silently_clipped():
    command = "echo " + "x" * 1600 + " IMPORTANT_TAIL"
    step = AgentStep(agent_id="a", proposed_tool_call=ToolCall(name="bash", input={"command": command}))
    state = build_monitor_state(step, Trajectory(agent_id="a"), PolicyContext())
    assert state["proposed_tool_call"]["input"]["command"] == command


def test_oversize_nested_action_is_held_even_when_backend_outages_fail_open(cfg):
    class MustNotScore(FakeBackend):
        def evaluate(self, state, questions):
            raise AssertionError("incomplete action must not be submitted as a complete assessment")

    cfg.state_max_chars = 200
    observer = SentinelObserver(cfg, backend=MustNotScore(), sinks=[])
    decision = observer.gate("a", ToolCall(name="lookup", input={"nested": {"value": "x" * 5000}}))
    assert decision.blocks
    assert decision.assessment_status == "incomplete_input"
    assert any(trigger.name == "incomplete_action" for trigger in decision.triggers)
    assert list(observer.audit.records())[-1]["payload"]["coverage"]["tool_input_complete"] is False
