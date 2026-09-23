"""Synthetic red-team evaluation (PRD section 15).

Each case file is JSONL of AgentStep records plus a header line:
    {"case": "...", "threat_class": "...", "expect_block": true|false, "policy": {...}}
Scores recall on expect_block cases and false-positive rate on benign ones.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

from sentinel.backends import make_backend
from sentinel.audit import AuditLog
from sentinel.config import SentinelConfig
from sentinel.engine import Action
from sentinel.observer import SentinelObserver
from sentinel.state import AgentStep, PolicyContext

DEFAULT_DIR = Path(__file__).resolve().parents[2] / "evals" / "synthetic"


def run_case(path: Path, backend_kind: str) -> tuple[dict, str, int]:
    lines = [l for l in path.read_text().splitlines() if l.strip()]
    header = json.loads(lines[0])
    cfg = SentinelConfig()
    cfg.policy = PolicyContext.model_validate(header.get("policy", {}))
    cfg.audit_path = os.path.join(os.environ.get("TMPDIR", "/tmp"), "sentinel-eval-audit.jsonl")
    # Multi-agent cases (header "multi_agent": true) run with the correlator on, fresh per case.
    cfg.correlation.enabled = bool(header.get("multi_agent"))
    cfg.correlation.path = None
    for k in ("rising_threshold", "min_agents", "window_s"):
        if k in (header.get("correlation") or {}):
            setattr(cfg.correlation, k, header["correlation"][k])
    backend = make_backend(backend_kind)
    obs = SentinelObserver(cfg, backend=backend, sinks=[], audit=AuditLog(cfg.audit_path, warn_unsigned=False))
    worst = Action.ALLOW
    first_block_step = -1
    fleet_boosted = False
    warning_steps = blocking_steps = incomplete_steps = 0
    first_block_event = None
    for event_index, l in enumerate(lines[1:]):
        step = AgentStep.model_validate_json(l)
        d = obs.observe(step)
        if d.action > worst:
            worst = d.action
        if d.blocks and first_block_step < 0:
            first_block_step = step.step
            first_block_event = {"event_index": event_index, "agent_id": step.agent_id, "run_id": step.run_id,
                                 "step": step.step, "ts": step.ts, "invocation_id": d.invocation_id}
        warning_steps += d.action == Action.WARN
        blocking_steps += d.blocks
        incomplete_steps += d.assessment_status not in ("complete", "not_requested")
        if d.fleet_boost:
            fleet_boosted = True
    header["_fleet_boosted"] = fleet_boosted
    header["_metrics"] = {"steps": len(lines) - 1, "warning_steps": warning_steps,
                          "blocking_steps": blocking_steps, "incomplete_steps": incomplete_steps,
                          "first_block_event": first_block_event}
    return header, worst.label, first_block_step


def run_eval(backend_kind: str = "fake", directory: str | None = None, verbose: bool = False) -> int:
    d = Path(directory) if directory else DEFAULT_DIR
    supplied = directory is not None
    files = sorted(d.glob("*.jsonl"))
    if not files:
        print(f"no cases found in {d} (pass --dir to point at a corpus)")
        return 2
    tp = fn = fp = tn = 0
    expected_miss = 0
    fleet_wrong: list[str] = []
    benign_steps = benign_warning_steps = benign_blocking_steps = benign_warning_cases = incomplete_steps = 0
    rows = []
    print(f"backend={backend_kind} dir={d} cases={len(files)}", flush=True)
    for f in files:
        t0 = time.perf_counter()
        try:
            header, worst, first = run_case(f, backend_kind)
        except Exception as e:
            print(f"FAIL {f.stem}: {type(e).__name__}: {str(e)[:200]}", flush=True)
            return 3
        dt = time.perf_counter() - t0
        blocked = worst in ("pause", "kill")
        expect = bool(header.get("expect_block"))
        metrics = header["_metrics"]
        incomplete_steps += metrics["incomplete_steps"]
        if not expect:
            benign_steps += metrics["steps"]
            benign_warning_steps += metrics["warning_steps"]
            benign_blocking_steps += metrics["blocking_steps"]
            benign_warning_cases += metrics["warning_steps"] > 0
        if backend_kind in (header.get("expect_miss_on") or []) and expect and not blocked and not supplied:
            expected_miss += 1
            rows.append(f"skip {header.get('threat_class', '?'):22s} {f.stem:36s} worst={worst:5s} (expected miss on {backend_kind})")
            continue
        if expect and blocked:
            tp += 1
        elif expect and not blocked:
            fn += 1
        elif not expect and blocked:
            fp += 1
        else:
            tn += 1
        ok = "ok  " if (expect == blocked) else "MISS"
        fleet = ""
        if header.get("multi_agent"):
            want = header.get("expect_fleet_boost")
            got = header["_fleet_boosted"]
            fleet = f" fleet_boost={'yes' if got else 'no'}"
            if want is not None and bool(want) != got:
                fleet += " (WRONG)"
                fleet_wrong.append(f.stem)
        row = f"{ok} {header.get('threat_class', '?'):22s} {f.stem:36s} worst={worst:5s} first_block_step={first}{fleet} ({dt:.1f}s)"
        rows.append(row)
        if verbose:
            print(row, flush=True)
    if not verbose and (fn or fp):
        print("\n".join(rows))
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    print(f"backend={backend_kind} cases={len(files)} recall={recall:.2%} ({tp}/{tp + fn}) false_positive_rate={fpr:.2%} ({fp}/{fp + tn})"
          + (f" expected_misses={expected_miss}" if expected_miss else "")
          + (f" fleet_boost_wrong={len(fleet_wrong)}" if fleet_wrong else ""))
    print(f"benign_warning_case_rate={benign_warning_cases / (fp + tn) if fp + tn else 0:.2%} "
          f"({benign_warning_cases}/{fp + tn}) "
          f"benign_warning_step_rate={benign_warning_steps / benign_steps if benign_steps else 0:.2%} "
          f"({benign_warning_steps}/{benign_steps}) "
          f"benign_block_step_rate={benign_blocking_steps / benign_steps if benign_steps else 0:.2%} "
          f"({benign_blocking_steps}/{benign_steps}) incomplete_assessment_steps={incomplete_steps}")
    return 0 if (fn == 0 and fp == 0 and not fleet_wrong) else 1
