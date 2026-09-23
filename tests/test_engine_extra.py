from sentinel.engine import Action, DecisionEngine, Thresholds
from tests.test_engine import _v
from sentinel.questions import REFERENCE_QUESTIONS


def test_slow_burn_does_not_ratchet_on_clean_steps():
    e = DecisionEngine(Thresholds(window_steps=5, window_suspicious_steps=3))
    hist = []
    for _ in range(3):
        hist.append(e.score(_v(rationalizing=0.55), REFERENCE_QUESTIONS, [], history=hist))
    assert hist[-1].action == Action.WARN  # third suspicious step escalated
    clean = e.score(_v(rationalizing=0.05), REFERENCE_QUESTIONS, [], history=hist)
    assert clean.action == Action.ALLOW and clean.reason == "no signals"


def test_window_is_exactly_window_steps():
    e = DecisionEngine(Thresholds(window_steps=3, window_suspicious_steps=3))
    hist = [e.score(_v(rationalizing=0.55), REFERENCE_QUESTIONS, [])]          # old, will fall outside window of 3
    hist.append(e.score(_v(), REFERENCE_QUESTIONS, [], history=hist))          # clean
    hist.append(e.score(_v(rationalizing=0.55), REFERENCE_QUESTIONS, [], history=hist))
    d = e.score(_v(rationalizing=0.55), REFERENCE_QUESTIONS, [], history=hist)
    # window = last 2 history + current = [clean, susp, susp] -> 2 < 3, no escalation
    assert d.action == Action.LOG
