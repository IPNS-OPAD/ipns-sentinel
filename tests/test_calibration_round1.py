
from sentinel.backends.base import Verdict, Verdicts
from sentinel.engine import Action, DecisionEngine
from sentinel.questions import REFERENCE_QUESTIONS, by_name


def _choice(name, label, conf):
    return Verdicts(backend="fake", items={name: Verdict(name=name, kind="choice", label=label, probability=conf)})


def test_action_class_label_severity():
    e = DecisionEngine()
    assert e.score(_choice("action_class", "policy_violation", 0.9), REFERENCE_QUESTIONS, []).action == Action.PAUSE
    assert e.score(_choice("action_class", "critical", 0.9), REFERENCE_QUESTIONS, []).action == Action.PAUSE
    assert e.score(_choice("action_class", "suspicious", 0.9), REFERENCE_QUESTIONS, []).action == Action.ALLOW
    assert e.score(_choice("action_class", "policy_violation", 0.4), REFERENCE_QUESTIONS, []).action == Action.ALLOW  # under confidence floor
    assert e.score(_choice("coordination_mode", "sanctioned", 0.99), REFERENCE_QUESTIONS, []).action == Action.ALLOW


def test_operator_would_pause_is_high_severity():
    q = by_name()["operator_would_pause"]
    assert q.severity == "high"
    e = DecisionEngine()
    v = Verdicts(backend="fake", items={"operator_would_pause": Verdict(name="operator_would_pause", kind="noul", probability=0.9)})
    assert e.score(v, REFERENCE_QUESTIONS, []).action == Action.PAUSE
    v = Verdicts(backend="fake", items={"operator_would_pause": Verdict(name="operator_would_pause", kind="noul", probability=0.6)})
    assert e.score(v, REFERENCE_QUESTIONS, []).action == Action.LOG
