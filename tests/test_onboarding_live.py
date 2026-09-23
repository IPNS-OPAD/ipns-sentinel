import json
import subprocess

import pytest

pytest.importorskip("typesafe_sdk")
pytest.importorskip("anthropic")

from sentinel.onboarding import live_smoke
from tests.test_provider_transport import provider_server


@pytest.mark.parametrize("fault", ["allow", "outage", "malformed"])
def test_byok_smoke_uses_only_explicit_fixture_key_and_never_executes_tools(tmp_path, monkeypatch, provider_server, fault):
    endpoint, state = provider_server
    state["primary"] = fault
    for name in ("TYPESAFE_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY"):
        monkeypatch.setenv(name, "private-ambient-canary")
    path = tmp_path / "credentials"
    path.write_text("export TYPESAFE_API_KEY=fixture-key\n")
    path.chmod(0o600)
    report = live_smoke(backend="jev", credentials=path, output_dir=tmp_path / "evidence", fixture_endpoint=endpoint)
    assert report["passed"] is (fault == "allow")
    assert report["executions"] == 0 and report["audit_verified"]
    assert state["paths"] == ["/v1/systemone"]  # No retries; canary needs no provider.
    assert json.loads((tmp_path / "evidence" / "summary.json").read_text()) == report
    for file in (tmp_path / "evidence").iterdir():
        assert b"private-ambient-canary" not in file.read_bytes()
        assert b"fixture-key" not in file.read_bytes()


def test_fixture_endpoint_rejects_real_credentials_before_network(tmp_path):
    path = tmp_path / "credentials"
    path.write_text("export TYPESAFE_API_KEY=not-a-fixture\n")
    path.chmod(0o600)
    report = live_smoke(backend="jev", credentials=path, output_dir=tmp_path / "evidence", fixture_endpoint="http://127.0.0.1:1")
    assert report["failure"] == "fixture_endpoint_invalid"
    assert not (tmp_path / "evidence").exists()


@pytest.mark.parametrize("backend,key_name", [("jev", "TYPESAFE_API_KEY"), ("claude", "ANTHROPIC_API_KEY")])
def test_smoke_does_not_inherit_routing_auth_headers_or_proxy_settings(tmp_path, monkeypatch, provider_server, backend, key_name):
    endpoint, state = provider_server
    state.update(primary="allow", fallback="allow")
    for name in ("TYPESAFE_BASE_URL", "ANTHROPIC_BASE_URL", "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY"):
        monkeypatch.setenv(name, "http://127.0.0.1:1")
    for name in ("TYPESAFE_DEFAULT_MODEL", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_PROFILE", "ANTHROPIC_CUSTOM_HEADERS"):
        monkeypatch.setenv(name, "ambient-routing-canary")
    real_popen = subprocess.Popen
    def checked_popen(*args, **kwargs):
        # OS boundary assertion prints names only on failure, never inherited values.
        assert set(kwargs["env"]) == {key_name}
        assert kwargs["env"][key_name] == "fixture-key"
        return real_popen(*args, **kwargs)
    monkeypatch.setattr(subprocess, "Popen", checked_popen)
    path = tmp_path / "credentials"
    path.write_text(f"export {key_name}=fixture-key\n")
    path.chmod(0o600)
    report = live_smoke(backend=backend, credentials=path, output_dir=tmp_path / "evidence", fixture_endpoint=endpoint)
    assert report["passed"] and report["executions"] == 0
    assert len(state["paths"]) == 1
