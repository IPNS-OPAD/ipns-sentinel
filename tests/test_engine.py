from sentinel.backends.base import Verdict, Verdicts
from sentinel.engine import Action, DecisionEngine, Thresholds
from sentinel.questions import REFERENCE_QUESTIONS, by_name


def _v(**probs):
    items = {}
    table = by_name()
    for name, p in probs.items():
        q = table[name]
        if q.kind == "noul":
            items[name] = Verdict(name=name, kind="noul", probability=p)
        elif q.kind == "score":
            items[name] = Verdict(name=name, kind="score", score=p, probability=0.9)
    return Verdicts(backend="fake", items=items)


def test_clean_step_allows():
    e = DecisionEngine()
    d = e.score(_v(covert_channel=0.05, exfiltration=0.02), REFERENCE_QUESTIONS, [])
    assert d.action == Action.ALLOW and not d.blocks


def test_single_critical_noul_pauses():
    e = DecisionEngine()
    d = e.score(_v(exfiltration=0.85), REFERENCE_QUESTIONS, [])
    assert d.action == Action.PAUSE and d.severity == "critical"


def test_two_criticals_kill():
    e = DecisionEngine()
    d = e.score(_v(exfiltration=0.9, credential_misuse=0.8), REFERENCE_QUESTIONS, [])
    assert d.action == Action.KILL


def test_score_threshold_pauses():
    e = DecisionEngine()
    d = e.score(_v(exfil_severity=4.2), REFERENCE_QUESTIONS, [])
    assert d.action == Action.PAUSE


def test_multi_suspicious_warns():
    e = DecisionEngine()
    d = e.score(_v(rationalizing=0.55, operator_would_pause=0.6), REFERENCE_QUESTIONS, [])
    assert d.action == Action.WARN


def test_slow_burn_escalates():
    e = DecisionEngine(Thresholds(window_suspicious_steps=3))
    hist = [e.score(_v(rationalizing=0.55), REFERENCE_QUESTIONS, []) for _ in range(2)]
    assert all(h.action == Action.LOG for h in hist)
    d = e.score(_v(rationalizing=0.55), REFERENCE_QUESTIONS, [], history=hist)
    assert d.action == Action.WARN


def test_correlation_boost_escalates():
    e = DecisionEngine()
    d = e.score(_v(covert_channel=0.5), REFERENCE_QUESTIONS, [], correlation_boost=2)
    assert d.action >= Action.PAUSE


def test_backend_failure_fail_open_and_closed():
    d = DecisionEngine(on_backend_error="open").score(None, REFERENCE_QUESTIONS, [], backend_failed=True)
    assert d.action == Action.ALLOW and d.fail_mode == "open"
    d = DecisionEngine(on_backend_error="closed").score(None, REFERENCE_QUESTIONS, [], backend_failed=True)
    assert d.action == Action.PAUSE and d.fail_mode == "closed"
