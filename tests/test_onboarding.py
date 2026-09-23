import json

from sentinel.cli import main


def test_offline_demo_assesses_without_executing_or_using_ambient_keys(monkeypatch, capsys, tmp_path):
    for name in ("TYPESAFE_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY"):
        monkeypatch.setenv(name, "private-ambient-canary")
    monkeypatch.setenv("SENTINEL_CONFIG", str(tmp_path / "absent-config"))
    monkeypatch.setenv("SENTINEL_AUDIT_KEY_FILE", str(tmp_path / "absent-key"))
    import socket
    def no_network(*args, **kwargs):
        raise AssertionError("offline demo attempted network access")
    monkeypatch.setattr(socket, "socket", no_network)
    assert main(["demo", "--mode", "observe"]) == 0
    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert report["scoring"] == "fake_fixture_not_detector_quality"
    assert report["mode"] == "observe" and report["executions"] == 0
    assert report["would_block"] == 1 and report["blocked"] == 0
    assert report["audit_verified"] and report["passed"]
    assert "private-ambient-canary" not in captured.out + captured.err


def test_offline_enforcement_demo_executes_only_fixed_arithmetic(capsys):
    assert main(["demo", "--mode", "enforce"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["outputs"] == [42] and report["executions"] == 1
    assert report["blocked"] == 1 and report["audit_verified"]


def test_live_smoke_requires_explicit_private_credentials_not_ambient_keys(monkeypatch, capsys, tmp_path):
    monkeypatch.setenv("TYPESAFE_API_KEY", "private-ambient-canary")
    import socket
    def no_network(*args, **kwargs):
        raise AssertionError("missing explicit credentials must fail before network access")
    monkeypatch.setattr(socket, "socket", no_network)
    assert main(["smoke", "--live", "--backend", "jev", "--credentials", str(tmp_path / "absent"),
                 "--output-dir", str(tmp_path / "result")]) == 2
    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert report["failure"] == "credential_file_invalid"
    assert "private-ambient-canary" not in captured.out + captured.err
    assert not (tmp_path / "result").exists()
