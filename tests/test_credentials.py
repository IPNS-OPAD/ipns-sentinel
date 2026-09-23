import pytest

from sentinel.credentials import load_provider_credentials
from sentinel.credentials import provider_environment


def test_loads_only_provider_exports_without_evaluating_shell(tmp_path):
    path = tmp_path / "secrets"
    path.write_text("export TYPESAFE_API_KEY='test-jev'\nexport ANTHROPIC_API_KEY=\"test-claude\"\n")
    path.chmod(0o600)
    assert load_provider_credentials(path) == {"TYPESAFE_API_KEY": "test-jev", "ANTHROPIC_API_KEY": "test-claude"}
    path.write_text("export TYPESAFE_API_KEY=$(touch stolen)\n")
    with pytest.raises(ValueError):
        load_provider_credentials(path)
    assert not (tmp_path / "stolen").exists()


def test_explicit_monitor_environment_never_keeps_unselected_provider_keys():
    parent = {"PATH": "/bin", "ANTHROPIC_API_KEY": "agent-secret", "TYPESAFE_API_KEY": "stale-secret",
              "OPENAI_API_KEY": "unselected-agent-secret"}
    assert provider_environment({"TYPESAFE_API_KEY": "monitor-secret"}, parent) == {
        "PATH": "/bin", "TYPESAFE_API_KEY": "monitor-secret"}
    assert parent["ANTHROPIC_API_KEY"] == "agent-secret"
    with pytest.raises(ValueError, match="provider"):
        provider_environment({"UNEXPECTED_SECRET": "no"}, parent)


def test_openai_agent_credentials_are_separate_from_monitor_credentials(tmp_path):
    path = tmp_path / "agent-secrets"
    path.write_text('export OPENAI_API_KEY="fixture-key"\n')
    path.chmod(0o600)
    assert load_provider_credentials(path, purpose="openai_agent") == {"OPENAI_API_KEY": "fixture-key"}
    with pytest.raises(ValueError):
        load_provider_credentials(path)
    path.write_text('export ANTHROPIC_API_KEY="fixture-monitor-key"\n')
    with pytest.raises(ValueError):
        load_provider_credentials(path, purpose="openai_agent")


def test_invalid_encoding_never_surfaces_secret_content(tmp_path):
    path = tmp_path / "secrets"
    path.write_bytes(b"export TYPESAFE_API_KEY=private-prefix\xff\n")
    path.chmod(0o600)
    with pytest.raises(ValueError, match="invalid credential file encoding") as error:
        load_provider_credentials(path)
    assert "private-prefix" not in str(error.value)


@pytest.mark.parametrize("contents", [
    "export UNRELATED_KEY=private\n", "export TYPESAFE_API_KEY=\n",
    "export TYPESAFE_API_KEY=a\nexport TYPESAFE_API_KEY=b\n",
    "export TYPESAFE_API_KEY='$(echo secret)'\n", "export TYPESAFE_API_KEY='unterminated\n",
])
def test_rejects_invalid_entries_without_echoing_values(tmp_path, contents):
    path = tmp_path / "secrets"
    path.write_text(contents)
    path.chmod(0o600)
    with pytest.raises(ValueError):
        load_provider_credentials(path)


def test_rejects_public_files_symlinks_and_nonregular_files(tmp_path):
    path = tmp_path / "secrets"
    path.write_text("export TYPESAFE_API_KEY=private")
    path.chmod(0o644)
    with pytest.raises(ValueError, match="private"):
        load_provider_credentials(path)
    path.chmod(0o600)
    link = tmp_path / "link"
    link.symlink_to(path)
    with pytest.raises(OSError):
        load_provider_credentials(link)
    import os
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo, 0o600)
    with pytest.raises(ValueError, match="regular"):
        load_provider_credentials(fifo)


@pytest.mark.parametrize("fallback", [{"fallback": "claude"}, {"fallback_config": {"kind": "claude"}}])
def test_broker_checks_effective_fallback_credentials_before_execution_setup(tmp_path, monkeypatch, fallback):
    from sentinel.cli import main
    from sentinel.config import SentinelConfig
    import sentinel.execution.docker
    cfg = SentinelConfig.model_validate({"backend": {"kind": "jev", **fallback}, "on_backend_error": "closed"})
    config = tmp_path / "config.json"
    config.write_text(cfg.model_dump_json())
    credentials = tmp_path / "credentials"
    credentials.write_text("export TYPESAFE_API_KEY=test-jev\n")
    credentials.chmod(0o600)
    monkeypatch.setenv("SENTINEL_AUDIT_KEY", "test-key-material-of-at-least-32-bytes")
    def no_docker(*args, **kwargs):
        pytest.fail("missing configured provider key must be rejected before Docker access")
    monkeypatch.setattr(sentinel.execution.docker, "DockerPythonRunner", no_docker)
    with pytest.raises(ValueError, match="lacks a configured provider key"):
        main(["broker", "--config", str(config), "--credentials", str(credentials),
              "--state-dir", str(tmp_path / "state"), "--agent-id", "a", "--run-id", "r", "--image", "unused"])
