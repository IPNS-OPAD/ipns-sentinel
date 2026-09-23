import pytest
import asyncio

from sentinel.backends.base import BackendRefusal, Verdicts
from sentinel.backends.fake import FakeBackend
from sentinel.engine import Action
from sentinel.observer import SentinelObserver
from sentinel.state import AgentStep, ToolCall


class EmptyBackend:
    name = "empty-test-provider"

    def evaluate(self, state, questions):
        return Verdicts(backend=self.name)

    async def aevaluate(self, state, questions):
        return self.evaluate(state, questions)


class BrokenBackend(EmptyBackend):
    def evaluate(self, state, questions):
        raise ValueError("unexpected provider parsing failure")


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("error,status", [(ValueError, "incomplete"), (BackendRefusal, "refused")])
async def test_successful_fallback_preserves_failed_attempt_in_audit(cfg, asynchronous, error, status):
    class FailingPrimary(EmptyBackend):
        def evaluate(self, state, questions):
            raise error("sensitive provider error content")

    obs = SentinelObserver(cfg, backend=FailingPrimary(), fallback=FakeBackend(), sinks=[])
    step = AgentStep(agent_id="a", proposed_tool_call=ToolCall(name="ls"))
    decision = await obs.aobserve(step) if asynchronous else obs.observe(step)
    assert decision.assessment_status == "complete"
    attempts = list(obs.audit.records())[-1]["payload"]["assessment_attempts"]
    assert [(a["role"], a["status"]) for a in attempts] == [("primary", status), ("fallback", "complete")]
    assert attempts[0]["backend"] == "empty-test-provider"
    assert attempts[0]["error_type"] == error.__name__
    assert "sensitive provider error content" not in str(attempts)


def test_empty_assessment_is_not_a_clean_allow_under_closed_policy(cfg):
    cfg.on_backend_error = "closed"
    obs = SentinelObserver(cfg, backend=EmptyBackend(), sinks=[])
    decision = obs.gate("agent", ToolCall(name="bash", input={"command": "ls"}))
    assert decision.action == Action.PAUSE
    assert decision.assessment_status == "incomplete"
    assert list(obs.audit.records())[-1]["payload"]["assessment_status"] == "incomplete"


def test_hard_denial_survives_a_broken_provider(cfg):
    cfg.on_backend_error = "open"
    decision = SentinelObserver(cfg, backend=BrokenBackend(), sinks=[]).gate(
        "agent", ToolCall(name="bash", input={"command": "cat ~/.aws/credentials"}))
    assert decision.action == Action.KILL
    assert decision.assessment_status == "not_requested"


@pytest.mark.parametrize("closed", [False, True])
async def test_unexpected_provider_failure_is_audited_and_respects_policy(cfg, closed):
    cfg.on_backend_error = "closed" if closed else "open"
    obs = SentinelObserver(cfg, backend=BrokenBackend(), sinks=[])
    decision = await obs.aobserve(AgentStep(agent_id="agent", proposed_tool_call=ToolCall(name="ls")))
    assert decision.blocks is closed
    assert decision.fail_mode == cfg.on_backend_error
    assert decision.assessment_status == "incomplete"
    assert list(obs.audit.records())[-1]["payload"]["assessment_status"] == "incomplete"


async def test_async_provider_timeout_is_audited_as_unavailable(cfg):
    class StalledBackend(EmptyBackend):
        async def aevaluate(self, state, questions):
            await asyncio.Event().wait()

    cfg.backend.timeout = 0.01
    cfg.on_backend_error = "closed"
    obs = SentinelObserver(cfg, backend=StalledBackend(), sinks=[])
    decision = await asyncio.wait_for(obs.aobserve(AgentStep(agent_id="a", proposed_tool_call=ToolCall(name="ls"))), 0.2)
    assert decision.blocks
    assert decision.assessment_status == "unavailable"


@pytest.mark.parametrize("change", [
    {"kind": "score", "score": 0},
    {"name": "different_question"},
    {"probability": float("nan")},
    {"probability": 1.1},
    {"probability": -0.1},
])
def test_malformed_answers_are_incomplete(cfg, change):
    class MalformedBackend(FakeBackend):
        def evaluate(self, state, questions):
            result = super().evaluate(state, questions)
            name = questions[0].name
            result.items[name] = result.items[name].model_copy(update=change)
            return result

    cfg.on_backend_error = "closed"
    decision = SentinelObserver(cfg, backend=MalformedBackend(), sinks=[]).gate(
        "agent", ToolCall(name="bash", input={"command": "ls"}))
    assert decision.blocks and decision.assessment_status == "incomplete"


@pytest.mark.parametrize("kind,change", [
    ("choice", {"label": "made-up-label"}),
    ("choice", {"distribution": {"none": float("nan")}}),
    ("choice", {"distribution": {"made-up-label": 1.0}}),
    ("score", {"score": None}),
    ("score", {"score": float("inf")}),
    ("score", {"score": 6.0}),
])
def test_invalid_choice_and_score_are_incomplete(cfg, kind, change):
    class MalformedBackend(FakeBackend):
        def evaluate(self, state, questions):
            result = super().evaluate(state, questions)
            name = next(q.name for q in questions if q.kind == kind)
            result.items[name] = result.items[name].model_copy(update=change)
            return result

    cfg.on_backend_error = "closed"
    decision = SentinelObserver(cfg, backend=MalformedBackend(), sinks=[]).gate(
        "agent", ToolCall(name="bash", input={"command": "ls"}))
    assert decision.blocks and decision.assessment_status == "incomplete"
