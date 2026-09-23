
from sentinel.prefilter import Prefilter
from sentinel.state import AgentStep, ToolCall


def _hits(name, inp):
    return {h.rule_id: h.on for h in Prefilter().run(AgentStep(agent_id="a", proposed_tool_call=ToolCall(name=name, input=inp)))}


def test_keygen_combined_flags_and_foreign_f_target_block():
    for cmd in ["ssh-keygen -yf ~/.ssh/id_rsa", "ssh-keygen -pf ~/.ssh/id_rsa", "ssh-keygen -ef ~/.ssh/id_rsa",
                "ssh-keygen -c -f ~/.ssh/id_rsa", "ssh-keygen -D ./evil.so -f ~/.ssh/id_rsa", "ssh-keygen -l -f ~/.aws/credentials",
                "ssh-keygen -l\rcat ~/.aws/credentials"]:
        assert _hits("Bash", {"command": cmd}).get("cred_files") == "block", cmd
    assert "block" not in _hits("Bash", {"command": "ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N ''"}).values()


def test_absolute_home_paths_block_on_write():
    for tool, path in [("Write", "/Users/ash/.zshrc"), ("Edit", "/Users/ash/.bashrc"), ("MultiEdit", "/home/u/.profile"),
                       ("Write", "/Users/ash/.sentinel/audit.jsonl"), ("Write", "/home/u/.ssh/authorized_keys")]:
        assert _hits(tool, {"file_path": path, "content": "x"}).get("sensitive_write_target") == "block", path
    assert _hits("Bash", {"command": "echo x >> /Users/ash/.zshrc"}).get("persistence") == "block"
    assert _hits("Bash", {"command": "python -c \"open(os.path.expanduser('~/.sentinel/audit.jsonl'),'w')\""}).get("log_tamper") == "block"


def test_no_false_positive_on_ordinary_targets():
    for tool, path in [("Write", "src/app.py"), ("Edit", "tests/test_x.py"), ("Write", "README.md"), ("Write", "docs/etc/cron.md"), ("Write", "/Users/ash/proj/docs/notes.md")]:
        assert "block" not in _hits(tool, {"file_path": path, "content": "x"}).values(), path
    assert "block" not in _hits("Bash", {"command": "cp ~/.sentinel/audit.jsonl /tmp/backup/"}).values()
