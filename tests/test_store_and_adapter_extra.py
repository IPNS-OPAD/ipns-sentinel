import io
import json
import sys

from sentinel.adapters import claude_code
from sentinel.correlation import Correlator, DecisionStore
from sentinel.engine import Action


def test_decision_store_roundtrip(tmp_path):
    s = DecisionStore(str(tmp_path / "f.db"))
    for i, (a, o) in enumerate([(1, True), (0, False), (2, True)]):
        s.add("a", "r", float(i), a, o)
    assert s.recent("a", "r", 2) == [(0, False), (2, True)]


def test_ratio_rule_needs_more_than_min_agents():
    c = Correlator(min_agents=3)
    for i in range(3):
        sig = c.record(f"a{i}", 0.9)
    assert sig.boost == 1


def test_tool_only_message_has_no_inherited_reasoning(tmp_path):
    t = tmp_path / "t.jsonl"
    recs = [
        {"type": "assistant", "message": {"id": "m1", "content": [{"type": "text", "text": "EARLIER benign plan"}, {"type": "tool_use", "id": "t1", "name": "Bash", "input": {"command": "ls"}}]}},
        {"type": "assistant", "message": {"id": "m2", "content": [{"type": "tool_use", "id": "t2", "name": "Bash", "input": {"command": "cat x"}}]}},
    ]
    t.write_text("\n".join(json.dumps(r) for r in recs) + "\n")
    reasoning, calls = claude_code.parse_transcript(str(t), "t2")
    assert reasoning == "" and [c.id for c in calls] == ["t1"]


def test_split_message_accumulates_text(tmp_path):
    t = tmp_path / "t.jsonl"
    recs = [
        {"type": "assistant", "message": {"id": "m1", "content": [{"type": "text", "text": "part one"}]}},
        {"type": "assistant", "message": {"id": "m1", "content": [{"type": "tool_use", "id": "t1", "name": "Bash", "input": {"command": "ls"}}]}},
        {"type": "assistant", "message": {"id": "m1", "content": ["not-a-dict-block"]}},
    ]
    t.write_text("\n".join(json.dumps(r) for r in recs) + "\n")
    reasoning, _ = claude_code.parse_transcript(str(t), "t1")
    assert reasoning == "part one"


def test_main_pre_exit_codes_on_error(monkeypatch, tmp_path):
    cfg = tmp_path / "c.yaml"
    cfg.write_text("on_backend_error: closed\naudit_path: %s\n" % (tmp_path / "a.jsonl"))
    monkeypatch.setenv("SENTINEL_CONFIG", str(cfg))
    monkeypatch.setattr(sys, "stdin", io.StringIO("not json"))
    assert claude_code.main_pre() == 2
    cfg.write_text("on_backend_error: open\naudit_path: %s\n" % (tmp_path / "a.jsonl"))
    monkeypatch.setattr(sys, "stdin", io.StringIO("not json"))
    assert claude_code.main_pre() == 1
