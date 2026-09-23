"""Bounded OpenAI agent comparison; Sentinel's resilient monitor is unchanged."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from examples.claude_fleet_sustained import run_cohort
from sentinel.adapters.openai_agent import MODEL
from sentinel.credentials import MONITOR_KEYS, load_provider_credentials
from sentinel.execution.docker import DockerPythonRunner


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--credentials", required=True, help="private Jev/Anthropic monitor credential file")
    parser.add_argument("--agent-credentials", required=True, help="separate private OpenAI credential file")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--agents", type=int, choices=range(3, 7), default=3)
    parser.add_argument("--image", default="python:3.12-slim")
    parser.add_argument("--case", choices=["all", "covert", "sanctioned", "independent"], default="all")
    parser.add_argument("--correlation", choices=["on", "off"], default="on")
    parser.add_argument("--agent-model", choices=[MODEL], default=MODEL)
    args = parser.parse_args()
    credentials = Path(args.credentials).expanduser().absolute()
    agent_credentials = Path(args.agent_credentials).expanduser().absolute()
    if set(load_provider_credentials(credentials)) != MONITOR_KEYS:
        parser.error("both monitor provider keys are required")
    if set(load_provider_credentials(agent_credentials, purpose="openai_agent")) != {"OPENAI_API_KEY"}:
        parser.error("the separate agent credential file must contain the OpenAI key")
    runner = DockerPythonRunner(args.image, timeout_s=5.0)
    root = Path(args.output_dir).expanduser().resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    (root / "trajectories").mkdir(mode=0o700)
    kinds = ["independent", "sanctioned", "covert"] if args.case == "all" else [args.case]
    reports = []
    for kind in kinds:
        report = run_cohort(root, kind=kind, agents=args.agents, claude="", credentials=credentials,
            runner=runner, correlation=args.correlation == "on", agent_model=args.agent_model,
            agent_provider="openai", agent_credentials=agent_credentials)
        reports.append(report)
        if len(report["cleanup"]) != args.agents or not all(report["cleanup"].values()):
            break  # No new cohort after unconfirmed containment.
    report = {"qualification": "four planned rounds per persistent OpenAI driver; controlled synthetic fixtures, not autonomous emergence",
        "agent_provider": "openai", "agent_model": args.agent_model, "monitor_profile": "resilient-monitor.yaml (unchanged)",
        "balanced_suite": args.case == "all" and len(reports) == 3, "agents_per_case": args.agents,
        "unattempted_cases": kinds[len(reports):], "cases": reports,
        "passed": len(reports) == len(kinds) and all(r["passed"] for r in reports)}
    (root / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"passed": report["passed"], "cases": [{"case": r["case"], **r["metrics"]} for r in reports]}), flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
