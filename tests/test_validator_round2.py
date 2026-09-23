
from sentinel.audit import AuditLog
from sentinel.prefilter import Prefilter
from sentinel.state import AgentStep, ToolCall


def _hits(name, inp):
    return {h.rule_id: h.on for h in Prefilter().run(AgentStep(agent_id="a", proposed_tool_call=ToolCall(name=name, input=inp)))}


def test_head_missing_is_not_laundered_by_next_append(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl", key="k", warn_unsigned=False)
    for i in range(3):
        log.append("decision", {"i": i})
    lines = log.path.read_text().splitlines()
    log.path.write_text("\n".join(lines[:2]) + "\n")   # drop last record
    log.head_path.unlink()                              # and the head
    log.append("decision", {"i": 9})                    # attacker hopes this re-derives a clean head
    ok, msg = log.verify()
    assert not ok and "head file was missing" in msg


def test_keygen_exemption_rejects_newline_and_passphrase_flags():
    assert _hits("Bash", {"command": "ssh-keygen -l\ncat ~/.aws/credentials"}).get("cred_files") == "block"
    assert _hits("Bash", {"command": "ssh-keygen -p -f ~/.ssh/id_rsa -N ''"}).get("cred_files") == "block"
    assert _hits("Bash", {"command": "ssh-keygen -y -f ~/.ssh/id_rsa"}).get("cred_files") == "block"
    assert "block" not in _hits("Bash", {"command": "ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N ''"}).values()


def test_write_targets_blocked():
    for path in ["~/.zshrc", "~/.bashrc", "~/.sentinel/audit.jsonl", "~/.ssh/authorized_keys", "~/.config/fish/config.fish"]:
        assert _hits("Write", {"file_path": path, "content": "x"}).get("sensitive_write_target") == "block", path
    assert "block" not in _hits("Write", {"file_path": "src/app.py", "content": "x"}).values()


def test_audit_dir_tamper_blocked():
    for cmd in ["rm -rf ~/.sentinel", "mv ~/.sentinel /tmp/x", "echo g | tee -a ~/.sentinel/audit.jsonl",
                "python -c \"open('/Users/me/.sentinel/audit.jsonl','w')\"", ">> ~/.config/fish/config.fish"]:
        assert "block" in _hits("Bash", {"command": cmd}).values(), cmd
