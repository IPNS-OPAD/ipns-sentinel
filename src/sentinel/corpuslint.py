"""Format check for a supplied corpus directory. Content-agnostic: validates the
header line and that every following line parses as an AgentStep."""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import ValidationError

from sentinel.state import AgentStep, PolicyContext

REQUIRED = ("case", "threat_class", "expect_block", "policy")


def lint(directory: str) -> int:
    d = Path(directory)
    files = sorted(d.glob("*.jsonl"))
    if not files:
        print(f"no .jsonl files in {d}")
        return 2
    problems = 0
    classes: dict[str, int] = {}
    for f in files:
        lines = [l for l in f.read_text().splitlines() if l.strip()]
        try:
            h = json.loads(lines[0])
        except (json.JSONDecodeError, IndexError):
            print(f"{f.name}: header line missing or not JSON"); problems += 1; continue
        missing = [k for k in REQUIRED if k not in h]
        if missing:
            print(f"{f.name}: header missing {missing}"); problems += 1
        if not isinstance(h.get("expect_block"), bool):
            print(f"{f.name}: expect_block must be true/false"); problems += 1
        try:
            PolicyContext.model_validate(h.get("policy") or {})
        except ValidationError as e:
            print(f"{f.name}: policy invalid: {e.errors()[0]['msg']}"); problems += 1
        if len(lines) < 2:
            print(f"{f.name}: no steps"); problems += 1
        agents: set[str] = set()
        for i, l in enumerate(lines[1:], start=2):
            try:
                s = AgentStep.model_validate_json(l)
                agents.add(s.agent_id)
                if not s.proposed_tool_call and not s.reasoning:
                    print(f"{f.name}:{i}: step has neither reasoning nor a tool call"); problems += 1
            except ValidationError as e:
                print(f"{f.name}:{i}: {e.errors()[0]['msg']}"); problems += 1
        tc = str(h.get("threat_class"))
        classes[tc] = classes.get(tc, 0) + 1
        if h.get("expect_block") and tc == "benign":
            print(f"{f.name}: benign case marked expect_block"); problems += 1
    print(f"{len(files)} files, {problems} problems; per class: " + ", ".join(f"{k}={v}" for k, v in sorted(classes.items())))
    benign = classes.get("benign", 0)
    if benign < len(files) / 3:
        print(f"warning: only {benign} benign cases; false-positive rate needs at least as many benign as attack cases to mean anything")
    return 0 if problems == 0 else 1
