
from sentinel.backends.base import BackendError, BackendRefusal
from sentinel.config import SentinelConfig
from sentinel.engine import Action, DecisionEngine
from sentinel.observer import SentinelObserver
from sentinel.questions import REFERENCE_QUESTIONS
from sentinel.state import ToolCall
from sentinel.audit import AuditLog


class _Refuses:
    name = "refuser"
    def evaluate(self, state, questions): raise BackendRefusal("classifier declined")
    async def aevaluate(self, state, questions): raise BackendRefusal("classifier declined")


class _Errors:
    name = "broken"
    def evaluate(self, state, questions): raise BackendError("boom")
    async def aevaluate(self, state, questions): raise BackendError("boom")


def _obs(tmp_path, backend, **cfgkw):
    cfg = SentinelConfig(**cfgkw); cfg.correlation.enabled = False; cfg.audit_path = str(tmp_path / "a.jsonl")
    return SentinelObserver(cfg, backend=backend, sinks=[], audit=AuditLog(cfg.audit_path, warn_unsigned=False))


def test_refusal_pauses_by_default_even_when_errors_fail_open(tmp_path):
    obs = _obs(tmp_path, _Refuses(), on_backend_error="open")
    d = obs.gate("a", ToolCall(name="bash", input={"command": "ls"}), reasoning="x")
    assert d.action == Action.PAUSE and d.fail_mode == "refusal:pause"
    assert any(t.name == "backend_refusal" for t in d.triggers)


def test_refusal_open_policy_allows(tmp_path):
    obs = _obs(tmp_path, _Refuses(), on_backend_refusal="open")
    d = obs.gate("a", ToolCall(name="bash", input={"command": "ls"}), reasoning="x")
    assert d.action == Action.ALLOW and d.fail_mode == "refusal:open"


def test_plain_error_still_follows_on_backend_error(tmp_path):
    d = _obs(tmp_path, _Errors(), on_backend_error="open").gate("a", ToolCall(name="bash", input={"command": "ls"}))
    assert d.action == Action.ALLOW and d.fail_mode == "open"


def test_engine_rejects_bad_policy():
    import pytest
    with pytest.raises(ValueError):
        DecisionEngine(on_backend_refusal="maybe")
