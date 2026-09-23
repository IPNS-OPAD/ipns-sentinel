"""Two bounded, synthetic real-monitor checks; credentials never enter reports."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import secrets
import time

from sentinel.config import SentinelConfig, BackendConfig
from sentinel.credentials import load_provider_credentials
from sentinel.execution.monitor import ProcessMonitor
from sentinel.state import AgentStep, ToolCall


def probe(kind: str, root: Path, credentials: dict[str, str]) -> dict:
    cfg = SentinelConfig(backend=BackendConfig(kind=kind, model="jev-1.13.0" if kind == "jev" else "claude-opus-5",
                                              timeout=30, max_retries=0), on_backend_error="closed")
    cfg.policy.task = "Calculate 6 * 7 in an isolated Python container."
    cfg.policy.allowed_scope = ["arithmetic", "python"]
    cfg.correlation.enabled = False
    cfg.audit_path = str(root / f"{kind}-audit.jsonl")
    key = secrets.token_hex(32).encode()
    key_path = root / f"{kind}-audit.key"
    key_path.write_bytes(key)
    key_path.chmod(0o600)
    name = "TYPESAFE_API_KEY" if kind == "jev" else "ANTHROPIC_API_KEY"
    started = time.perf_counter()
    try:
        with ProcessMonitor(cfg, audit_key=key, timeout_s=35, credentials={name: credentials[name]}) as monitor:
            decision = monitor.evaluate(AgentStep(agent_id="probe", run_id=f"probe-{kind}",
                proposed_tool_call=ToolCall(name="python", input={"code": "print(6 * 7)"})))
        return {"backend": kind, "action": decision.action.label, "assessment_status": decision.assessment_status,
                "resolved_model": decision.verdicts.model if decision.verdicts else None,
                "input_tokens": decision.verdicts.input_tokens if decision.verdicts else None,
                "elapsed_s": round(time.perf_counter() - started, 3)}
    except Exception as error:
        return {"backend": kind, "error_type": type(error).__name__, "elapsed_s": round(time.perf_counter() - started, 3)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--credentials", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()
    credentials = load_provider_credentials(args.credentials)
    root = Path(args.output_dir).resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda kind: probe(kind, root, credentials), ["jev", "claude"]))
    report = {"synthetic_only": True, "results": results}
    (root / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if all(r.get("assessment_status") == "complete" for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
