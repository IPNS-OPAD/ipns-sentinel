import sys
import json
from types import SimpleNamespace

import pytest

from sentinel.backends.base import BackendInvalidResponse, BackendRefusal
from sentinel.backends.claude import ClaudeSystemOneBackend
from sentinel.backends.jev import JevBackend
from sentinel.questions import REFERENCE_QUESTIONS
from sentinel.config import SentinelConfig
from sentinel.observer import SentinelObserver
from sentinel.state import ToolCall


class SDKResponseValidationError(Exception):
    pass


def raw_client(parse, stop_reason="end_turn"):
    def raw_parse(**kwargs):
        return SimpleNamespace(json=lambda: {"stop_reason": stop_reason}, parse=lambda: parse(**kwargs))
    return SimpleNamespace(beta=SimpleNamespace(messages=SimpleNamespace(
        with_raw_response=SimpleNamespace(parse=raw_parse))))


def install_claude_response(monkeypatch, raw, stop_reason="end_turn"):
    def parse(**kwargs):
        return SimpleNamespace(parsed_output=kwargs["output_format"].model_validate_json(raw),
            stop_reason="end_turn", model="test-model", usage=SimpleNamespace(input_tokens=1),
            content=[SimpleNamespace(type="text", text=raw)])
    client = raw_client(parse, stop_reason)
    monkeypatch.setitem(sys.modules, "anthropic", SimpleNamespace(
        Anthropic=lambda **kw: client, AsyncAnthropic=lambda **kw: client))


def test_duplicate_provider_answers_cannot_overwrite_each_other(monkeypatch):
    question = REFERENCE_QUESTIONS[0]
    field = json.dumps(question.name)
    raw = '{' + field + ':{"probability_yes":0.9},' + field + ':{"probability_yes":0.0}}'
    install_claude_response(monkeypatch, raw)
    with pytest.raises(BackendInvalidResponse):
        ClaudeSystemOneBackend().evaluate({}, [question])


def test_jev_rejects_unrequested_answers(monkeypatch):
    response = SimpleNamespace(nouls={REFERENCE_QUESTIONS[0].name: SimpleNamespace(noul=0.0),
                                     "unexpected": SimpleNamespace(noul=0.0)}, choices={}, scores={})
    client = SimpleNamespace(system_one=lambda *args: response)
    monkeypatch.setitem(sys.modules, "typesafe_sdk", SimpleNamespace(
        TypeSafeAPIResponseValidationError=SDKResponseValidationError,
        TypeSafeClient=lambda **kw: client, AsyncTypeSafeClient=lambda **kw: client,
        RetryPolicy=lambda **kw: SimpleNamespace(**kw)))
    with pytest.raises(BackendInvalidResponse):
        JevBackend().evaluate({}, [REFERENCE_QUESTIONS[0]])


def test_fallback_uses_its_own_model_and_applies_its_timeout(monkeypatch, tmp_path):
    recorded = {}

    def broken_jev(*args):
        raise RuntimeError("provider unavailable")

    monkeypatch.setitem(sys.modules, "typesafe_sdk", SimpleNamespace(
        TypeSafeAPIResponseValidationError=SDKResponseValidationError,
        TypeSafeClient=lambda **kw: SimpleNamespace(system_one=broken_jev),
        AsyncTypeSafeClient=lambda **kw: None, RetryPolicy=lambda **kw: SimpleNamespace(**kw)))
    question = REFERENCE_QUESTIONS[0]
    response = SimpleNamespace(parsed_output=SimpleNamespace(nouls=[SimpleNamespace(
        name=question.name, probability_yes=0.0)], choices=[], scores=[]),
        stop_reason="end_turn", model="fallback-model", usage=SimpleNamespace(input_tokens=1))

    def parse(**kwargs):
        recorded["request"] = kwargs
        payload = {question.name: {"probability_yes": 0.0}}
        response.parsed_output = kwargs["output_format"].model_validate(payload)
        response.content = [SimpleNamespace(type="text", text=json.dumps(payload))]
        return response

    def client(**kwargs):
        recorded["client"] = kwargs
        return raw_client(parse)

    monkeypatch.setitem(sys.modules, "anthropic", SimpleNamespace(Anthropic=client, AsyncAnthropic=client))
    cfg = SentinelConfig.model_validate({
        "backend": {"kind": "jev", "model": "primary-only-model", "fallback": "claude",
                    "fallback_config": {"kind": "claude", "model": "fallback-model", "timeout": 0.25}},
        "questions": [question.name], "audit_path": str(tmp_path / "audit.jsonl"),
    })
    decision = SentinelObserver(cfg, sinks=[]).gate("agent", ToolCall(name="ls"))
    assert recorded["request"]["model"] == "fallback-model"
    assert recorded["client"]["timeout"] == 0.25
    assert recorded["client"]["max_retries"] == 0
    assert decision.assessment_status == "complete"


def test_hard_denial_does_not_require_provider_initialization(monkeypatch, tmp_path):
    def unavailable(**kwargs):
        raise RuntimeError("credentials unavailable")

    monkeypatch.setitem(sys.modules, "typesafe_sdk", SimpleNamespace(
        TypeSafeAPIResponseValidationError=SDKResponseValidationError,
        TypeSafeClient=unavailable, AsyncTypeSafeClient=unavailable, RetryPolicy=lambda **kw: SimpleNamespace(**kw)))
    cfg = SentinelConfig(backend={"kind": "jev"}, audit_path=str(tmp_path / "audit.jsonl"))
    decision = SentinelObserver(cfg, sinks=[]).gate("agent", ToolCall(name="bash", input={
        "command": "cat ~/.aws/credentials"}))
    assert decision.blocks and decision.assessment_status == "not_requested"


def test_jev_retry_budget_is_explicit(monkeypatch):
    recorded = {}

    def client(**kwargs):
        recorded.update(kwargs)
        return SimpleNamespace()

    monkeypatch.setitem(sys.modules, "typesafe_sdk", SimpleNamespace(
        TypeSafeAPIResponseValidationError=SDKResponseValidationError,
        TypeSafeClient=client, AsyncTypeSafeClient=client,
        RetryPolicy=lambda **kwargs: SimpleNamespace(**kwargs)))
    JevBackend(timeout=0.25, max_retries=0)
    assert recorded["retry"].max_retries == 0
    assert recorded["retry"].timeout == 0.25


def test_claude_structured_output_is_locked_to_requested_question_identity(monkeypatch):
    questions = [q for q in REFERENCE_QUESTIONS if q.name in {"covert_channel", "coordination_mode", "exfil_severity"}]
    payload = {"covert_channel": {"probability_yes": 0.0},
               "coordination_mode": {"label": "none", "confidence": 1.0},
               "exfil_severity": {"score": 0.0, "confidence": 1.0}}
    def parse(**kwargs):
        schema = kwargs["output_format"]
        parsed = schema.model_validate(payload)
        return SimpleNamespace(parsed_output=parsed, stop_reason="end_turn", model="fixture",
            usage=SimpleNamespace(input_tokens=1), content=[SimpleNamespace(type="text", text=json.dumps(payload))])
    client = raw_client(parse)
    monkeypatch.setitem(sys.modules, "anthropic", SimpleNamespace(Anthropic=lambda **kw: client, AsyncAnthropic=lambda **kw: client))
    verdicts = ClaudeSystemOneBackend().evaluate({}, questions)
    assert set(verdicts.items) == set(payload)
    assert verdicts.items["coordination_mode"].label == "none"


@pytest.mark.parametrize("payload", [
    {},
    {"covert_channel": {"probability_yes": 0}, "unknown": {"probability_yes": 0}},
    {"covert_channel": {"probability_yes": 1.1}},
    {"coordination_mode": {"label": "not-an-offered-label", "confidence": 1}},
    {"exfil_severity": {"score": 99, "confidence": 1}},
])
def test_malformed_claude_answers_are_incomplete_not_refusals(monkeypatch, payload):
    name = next(iter(payload), "covert_channel")
    questions = [q for q in REFERENCE_QUESTIONS if q.name == name]
    install_claude_response(monkeypatch, json.dumps(payload))
    with pytest.raises(BackendInvalidResponse) as error:
        ClaudeSystemOneBackend().evaluate({}, questions)
    assert error.value.issue == "schema"


def test_claude_explicit_refusal_is_checked_before_structured_parsing(monkeypatch):
    install_claude_response(monkeypatch, "declined", stop_reason="refusal")
    with pytest.raises(BackendRefusal):
        ClaudeSystemOneBackend().evaluate({}, [REFERENCE_QUESTIONS[0]])
