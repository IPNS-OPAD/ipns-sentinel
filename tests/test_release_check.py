import importlib.util
import os
from pathlib import Path
import secrets
import shutil
import subprocess

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check_release.py"
spec = importlib.util.spec_from_file_location("release_check", SCRIPT)
release_check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release_check)


@pytest.mark.parametrize("name", [".env", ".env.local", "audit.key", "private.pem", ".sentinel/run/audit.jsonl", ".sentinel_env", ".DS_Store"])
def test_release_rejects_private_paths(name):
    assert release_check.private_path(name)
    assert not release_check.private_path(".env.example")


@pytest.mark.parametrize("provider", ["github", "generic"])
def test_real_scanner_allows_only_exact_inert_fixture_and_finds_new_secret(tmp_path, provider):
    binary = os.environ.get("SENTINEL_TEST_GITLEAKS")
    if not binary:
        pytest.skip("opt-in pinned Gitleaks integration")
    def git(*args):
        subprocess.run(["git", "-C", str(tmp_path), *args], capture_output=True, check=True)
    git("init", "--quiet")
    shutil.copyfile(SCRIPT.parents[1] / ".gitleaks.toml", tmp_path / ".gitleaks.toml")
    test_dir = tmp_path / "tests"
    test_dir.mkdir()
    path = test_dir / "test_credentials.py"
    fixture = "test-key-material-" + "of-at-least-32-bytes"
    path.write_text("audit_key = " + repr(fixture) + "\n")
    git("add", ".")
    git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "fixture")
    assert release_check.check(tmp_path, binary)["passed"]
    # Synthetic, unusable canary, assembled at runtime; never a provider key.
    token = "ghp_" + secrets.token_hex(18) if provider == "github" else secrets.token_urlsafe(48)
    path.write_text(path.read_text() + "api_key = " + repr(token) + "\n")
    report = release_check.check(tmp_path, binary)
    assert not report["passed"] and report["findings"]
    assert token not in str(report)
    git("add", ".")
    git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "synthetic canary")
    path.write_text("# no current credential\n")
    report = release_check.check(tmp_path, binary)
    assert not report["passed"] and any(item["scope"] == "history" for item in report["findings"])
    assert token not in str(report)
