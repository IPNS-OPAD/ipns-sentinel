"""sentinel CLI: hooks, audit verification, replay, eval, question listing."""

from __future__ import annotations

import argparse
import json
import os
import sys

from sentinel import __version__


def _cmd_hook(a: argparse.Namespace) -> int:
    from sentinel.adapters import claude_code

    return claude_code.main_pre() if a.event == "pre" else claude_code.main_post()


def _cmd_audit(a: argparse.Namespace) -> int:
    from pathlib import Path
    from sentinel.audit import AuditLog, AuditCheckpoint
    from sentinel.config import SentinelConfig

    path = a.path or os.path.expanduser(SentinelConfig.load().audit_path)
    log = AuditLog(path)
    checkpoint = AuditCheckpoint.model_validate_json(Path(a.checkpoint).read_text()) if a.checkpoint else None
    ok, msg = log.verify(checkpoint=checkpoint)
    if a.export_checkpoint:
        if not ok:
            print("FAIL " + msg)
            return 2
        print(log.checkpoint().model_dump_json())
        return 0
    print(("OK " if ok else "FAIL ") + msg)
    return 0 if ok else 2


def _cmd_questions(a: argparse.Namespace) -> int:
    from sentinel.questions import REFERENCE_QUESTIONS

    for q in REFERENCE_QUESTIONS:
        print(f"{q.name:24s} {q.kind:6s} {q.severity:10s} {q.threat_class:22s} {q.instructions[:80]}")
    return 0


def _cmd_replay(a: argparse.Namespace) -> int:
    """Replay a trajectory file: JSONL of AgentStep records."""
    from sentinel.backends import make_backend
    from sentinel.config import SentinelConfig
    from sentinel.observer import SentinelObserver
    from sentinel.state import AgentStep

    cfg = SentinelConfig.load(a.config)
    backend = make_backend(a.backend, **(cfg.backend.primary_kwargs() if a.backend == cfg.backend.kind else {})) if a.backend else None
    obs = SentinelObserver(cfg, backend=backend, sinks=[])
    worst = 0
    with open(a.file) as f:
        for line in f:
            if not line.strip():
                continue
            step = AgentStep.model_validate_json(line)
            d = obs.observe(step)
            worst = max(worst, int(d.action))
            print(json.dumps({"agent": step.agent_id, "step": step.step, "action": d.action.label, "reason": d.reason}))
    return 0


def _cmd_corpus_lint(a: argparse.Namespace) -> int:
    from sentinel.corpuslint import lint

    return lint(a.dir)


def _cmd_eval(a: argparse.Namespace) -> int:
    from sentinel.evalrun import run_eval

    return run_eval(a.backend, a.dir, verbose=a.verbose)


def _cmd_broker(a: argparse.Namespace) -> int:
    from pathlib import Path
    from sentinel.audit import AuditLog
    from sentinel.config import SentinelConfig
    from sentinel.execution.broker import ExecutionBroker
    from sentinel.credentials import load_provider_credentials
    from sentinel.execution.docker import DockerPythonRunner
    from sentinel.execution.monitor import ProcessMonitor
    from sentinel.execution.protocol import serve

    cfg = SentinelConfig.load(a.config)
    credentials = load_provider_credentials(a.credentials) if a.credentials else None
    if credentials is not None:
        secondary = cfg.backend.secondary()
        kinds = {cfg.backend.kind, secondary.kind if secondary else None}
        names = {"jev": "TYPESAFE_API_KEY", "claude": "ANTHROPIC_API_KEY"}
        selected = {names[kind] for kind in kinds if kind in names}
        if selected - credentials.keys():
            raise ValueError("credential file lacks a configured provider key")
        credentials = {k: v for k, v in credentials.items() if k in selected}
    if cfg.backend.kind == "fake" and not a.demo_fake:
        raise ValueError("fake scoring is demo-only; explicitly pass --demo-fake")
    state = Path(a.state_dir).expanduser().resolve()
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    audit = AuditLog(state / "execution.jsonl")
    if len(audit.key) < 32:
        raise ValueError("broker requires a protected audit key of at least 32 bytes")
    cfg.audit_path = str(state / "monitor.jsonl")
    cfg.correlation.path = str(state / "fleet.db")
    if a.correlation_state:
        cfg.correlation.path = str(Path(a.correlation_state).expanduser().resolve())
    peer_context = None
    peer_context_for = None
    if a.turn_context_dir:
        from sentinel.execution.turns import load_turn_context

        if a.transport != "mcp" or a.peer_context_file:
            raise ValueError("turn contexts require MCP and cannot be combined with a fixed peer snapshot")
        turn_directory = Path(a.turn_context_dir).expanduser().absolute()
        peer_context_for = lambda invocation: load_turn_context(turn_directory, agent_id=a.agent_id,
                                                               run_id=a.run_id, invocation_id=invocation)
    if a.peer_context_file:
        if a.transport != "mcp":
            raise ValueError("operator peer context requires the MCP transport")
        with Path(a.peer_context_file).open() as stream:
            peer_context = stream.read(2001)
        if len(peer_context) > 2000:
            raise ValueError("operator peer context exceeds monitor coverage")
    runner = DockerPythonRunner(a.image, timeout_s=a.tool_timeout)
    if a.supervise:
        from sentinel.execution.supervision import supervise

        # The child receives the same fixed configuration and immutable image.
        # It inherits stdio directly; the parent exposes no additional agent API.
        command = [sys.executable, "-I", "-m", "sentinel.cli", "broker", "--config", a.config,
            "--state-dir", str(state), "--agent-id", a.agent_id, "--run-id", a.run_id,
            "--image", runner.image, "--tool-timeout", str(a.tool_timeout),
            "--monitor-timeout", str(a.monitor_timeout), "--transport", a.transport]
        for flag, value in [("--credentials", a.credentials), ("--peer-context-file", a.peer_context_file),
                            ("--correlation-state", a.correlation_state), ("--turn-context-dir", a.turn_context_dir)]:
            if value:
                command += [flag, value]
        if a.demo_fake:
            command.append("--demo-fake")

        def recover() -> bool:
            with ProcessMonitor(cfg, audit_key=audit.key, timeout_s=a.monitor_timeout, credentials={}) as monitor:
                broker = ExecutionBroker(agent_id=a.agent_id, run_id=a.run_id, path=state / "execution.db",
                    monitor=monitor, runner=runner, audit=audit)
                return broker.hold(operator="supervisor", reason="broker child exited; operator review required")

        return supervise(command, recover=recover, audit=AuditLog(state / "supervisor.jsonl", key=audit.key))
    with ProcessMonitor(cfg, audit_key=audit.key, timeout_s=a.monitor_timeout, credentials=credentials) as monitor:
        broker = ExecutionBroker(agent_id=a.agent_id, run_id=a.run_id, path=state / "execution.db",
                                 monitor=monitor, runner=runner, audit=audit)
        if a.transport == "mcp":
            import anyio
            from sentinel.execution.mcp import serve as serve_mcp
            anyio.run(serve_mcp, broker, peer_context, peer_context_for)
        else:
            serve(broker, sys.stdin, sys.stdout)
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="sentinel", description="Sentinel agent monitor")
    p.add_argument("--version", action="version", version=f"sentinel {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    from sentinel.onboarding import command_demo, command_smoke
    demo = sub.add_parser("demo", help="key-free offline walkthrough; simulated scoring, not detector quality")
    demo.add_argument("--mode", choices=["observe", "enforce"], default="observe")
    demo.set_defaults(fn=command_demo)

    smoke = sub.add_parser("smoke", help="opt-in BYOK live monitor check; no tools execute, provider charges may apply")
    smoke.add_argument("--live", action="store_true", required=True)
    smoke.add_argument("--backend", choices=["jev", "claude"], required=True)
    smoke.add_argument("--credentials", required=True, help="your private provider export file; no ambient-key fallback")
    smoke.add_argument("--output-dir", required=True, help="new private evidence directory")
    smoke.add_argument("--model", help="explicit monitor model; no automatic model fallback")
    smoke.set_defaults(fn=command_smoke)

    h = sub.add_parser("hook", help="Claude Code hook entrypoints (stdin JSON)")
    h.add_argument("event", choices=["pre", "post"])
    h.set_defaults(fn=_cmd_hook)

    au = sub.add_parser("audit", help="verify the hash chain and signatures of the audit log")
    au.add_argument("path", nargs="?")
    au.add_argument("--checkpoint", help="independently retained trusted prefix to verify")
    au.add_argument("--export-checkpoint", action="store_true", help="print a verified prefix for independent retention")
    au.set_defaults(fn=_cmd_audit)

    q = sub.add_parser("questions", help="print the reference question set")
    q.set_defaults(fn=_cmd_questions)

    r = sub.add_parser("replay", help="replay a JSONL trajectory through the observer")
    r.add_argument("file")
    r.add_argument("--backend", choices=["fake", "jev", "claude"])
    r.add_argument("--config")
    r.set_defaults(fn=_cmd_replay)

    cl = sub.add_parser("corpus-lint", help="format-check a supplied corpus directory")
    cl.add_argument("dir")
    cl.set_defaults(fn=_cmd_corpus_lint)

    e = sub.add_parser("eval", help="run the synthetic red-team suite")
    e.add_argument("--backend", default="fake", choices=["fake", "jev", "claude"])
    e.add_argument("--dir", default=None)
    e.add_argument("-v", "--verbose", action="store_true")
    e.set_defaults(fn=_cmd_eval)

    b = sub.add_parser("broker", help="experimental operator-owned JSONL execution broker (local Docker required)")
    b.add_argument("--config", required=True)
    b.add_argument("--state-dir", required=True)
    b.add_argument("--agent-id", required=True)
    b.add_argument("--run-id", required=True)
    b.add_argument("--image", required=True, help="trusted, already-local Python image; resolved to immutable ID")
    b.add_argument("--monitor-timeout", type=float, default=5.0)
    b.add_argument("--tool-timeout", type=float, default=10.0)
    b.add_argument("--demo-fake", action="store_true", help="explicitly allow fake scoring for a local demo")
    b.add_argument("--transport", choices=["jsonl", "mcp"], default="jsonl")
    b.add_argument("--credentials", help="private literal provider export file, loaded only by the trusted broker")
    b.add_argument("--peer-context-file", help="operator-owned snapshot actually delivered to this agent; MCP only")
    b.add_argument("--turn-context-dir", help="private invocation-bound operator snapshots for persistent MCP sessions")
    b.add_argument("--correlation-state", help="operator-owned fleet database shared only by the intended cohort")
    b.add_argument("--supervise", action="store_true", help="trusted parent holds/reclaims registered containers when its broker child exits")
    b.set_defaults(fn=_cmd_broker)

    a = p.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
