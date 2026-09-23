"""Local trusted parent supervision, not protection against parent/host death."""
from __future__ import annotations

from collections.abc import Callable
import subprocess

from sentinel.audit import AuditLog


def supervise(command: list[str], *, recover: Callable[[], bool], audit: AuditLog) -> int:
    """Inherit the agent pipe, wait for one broker child, then hold/recover its run.

    No automatic restart or resume. The supplied recovery must target only the
    child's protected journal and registered containers. The operator must keep
    this parent and its state outside the agent's authority.
    """
    child = subprocess.Popen(command, start_new_session=True)
    try:
        audit.append("broker_supervision_started", {"pid": child.pid})
        return child.wait()
    finally:
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=2)
        confirmed = False
        try:
            confirmed = recover()
        finally:
            audit.append("broker_supervision_recovered", {"pid": child.pid, "returncode": child.returncode,
                                                         "containment_confirmed": confirmed})
        if not confirmed:
            raise RuntimeError("broker containment unconfirmed; operator recovery required")
