import json

from sentinel.adapters.claude_code import handle_pre, handle_post, parse_transcript
from sentinel.audit import AuditLog


def _transcript(path):
    recs = [
        {"type": "user", "message": {"content": "fix the test"}},
        {"type": "assistant", "message": {"content": [{"type": "text", "text": "I'll run the suite first."},
                                                       {"type": "tool_use", "id": "t1", "name": "Bash", "input": {"command": "pytest -q"}}]}},
        {"type": "assistant", "message": {"content": [{"type": "text", "text": "One failure. Read the parser."},
                                                       {"type": "tool_use", "id": "t2", "name": "Bash", "input": {"command": "cat src/parser.py"}}]}},
    ]
    path.write_text("\n".join(json.dumps(r) for r in recs) + "\n")


def test_parse_transcript(tmp_path):
    t = tmp_path / "t.jsonl"
    _transcript(t)
    reasoning, calls = parse_transcript(str(t), "t2")
    assert "Read the parser" in reasoning
    assert [c.name for c in calls] == ["Bash"] and calls[0].input["command"] == "pytest -q"


def test_pre_hook_allows_clean(cfg, tmp_path):
    t = tmp_path / "t.jsonl"
    _transcript(t)
    out = handle_pre({"session_id": "s1", "transcript_path": str(t), "tool_name": "Bash", "tool_input": {"command": "cat src/parser.py"}, "tool_use_id": "t2"}, cfg)
    assert out is None


def test_pre_hook_denies_block(cfg, tmp_path):
    out = handle_pre({"session_id": "s1", "tool_name": "Bash", "tool_input": {"command": "cat ~/.aws/credentials"}, "tool_use_id": "t9"}, cfg)
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_post_hook_records_execution(cfg):
    handle_post({"session_id": "s1", "tool_name": "Bash", "tool_input": {"command": "ls"}, "tool_use_id": "t3", "tool_response": {"type": "text", "text": "a b c"}}, cfg)
    recs = list(AuditLog(cfg.audit_path).records())
    assert recs[-1]["kind"] == "tool_executed" and recs[-1]["payload"]["tool_use_id"] == "t3"
