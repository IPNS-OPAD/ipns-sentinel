"""Redacted local release check. No provider credentials, network or uploads.

Requires Gitleaks 8.30.1 and full local Git history. Scan a temporary copy of
tracked/non-ignored source, not ignored runtime evidence or the user's home.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import tempfile


def git(root: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(root), *args], stderr=subprocess.DEVNULL)


def private_path(name: str) -> bool:
    path = Path(name)
    return (".sentinel" in path.parts or path.name == ".DS_Store" or path.suffix in {".key", ".pem", ".env"}
        or path.name in {".sentinel_env", ".sentinel_openai_env"}
        or (path.name.startswith(".env") and path.name != ".env.example"))


def scan(binary: str, config: Path, target: Path, *, history: bool) -> list[dict]:
    args = [binary, "git" if history else "dir", "--config", str(config), "--redact=100", "--no-banner",
            "--ignore-gitleaks-allow", "--timeout=120", "--report-format=json", "--report-path=-", "--log-level=error"]
    if history:
        args += ["--log-opts=--all"]
    process = subprocess.run([*args, str(target)], capture_output=True, timeout=130)
    if process.returncode not in {0, 1}:
        raise RuntimeError("scanner failed")
    findings = json.loads(process.stdout)
    if not isinstance(findings, list) or (process.returncode == 1 and not findings):
        raise RuntimeError("invalid scanner report")
    # Never forward scanner matches, secret fields or arbitrary stderr.
    return [{"scope": "history" if history else "worktree", "rule": item["RuleID"],
             "file": item["File"], "line": item["StartLine"]} for item in findings]


def check(root: Path, binary: str) -> dict:
    root = root.resolve()
    if git(root, "rev-parse", "--is-shallow-repository").strip() != b"false":
        raise ValueError("full history is required")
    if subprocess.check_output([binary, "version"], stderr=subprocess.DEVNULL).strip() != b"8.30.1":
        raise ValueError("use the pinned scanner version")
    config = root / ".gitleaks.toml"
    files = sorted(set(filter(None, git(root, "ls-files", "--cached", "--others", "--exclude-standard", "-z").decode().split("\0"))))
    unsafe = [name for name in files if private_path(name) or (root / name).is_symlink()]
    history_names = [line.split(" ", 1)[1] for line in git(root, "rev-list", "--objects", "--all").decode().splitlines() if " " in line]
    historical_private = sorted(set(name for name in history_names if private_path(name)))
    if unsafe:
        return {"passed": False, "failure": "private_release_paths", "paths": unsafe}
    with tempfile.TemporaryDirectory(prefix="sentinel-release-scan-") as directory:
        snapshot = Path(directory)
        for name in files:
            source = root / name
            if not source.is_file() or not source.resolve().is_relative_to(root):
                raise ValueError("release source is missing or outside repository")
            target = snapshot / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        findings = scan(binary, config, snapshot, history=False) + scan(binary, config, root, history=True)
    return {"passed": not findings, "scanner": "gitleaks 8.30.1", "source_files": len(files),
        "commits": int(git(root, "rev-list", "--all", "--count")), "findings": findings,
        "historical_private_paths_for_review": historical_private,
        "note": "Secret scan only; historical metadata, licensing and release approval require separate review."}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--gitleaks", default="gitleaks")
    args = parser.parse_args()
    try:
        report = check(args.repo, args.gitleaks)
    except Exception:
        report = {"passed": False, "failure": "release_check_incomplete"}
    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
