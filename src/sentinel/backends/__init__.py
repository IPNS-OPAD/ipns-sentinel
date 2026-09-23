from sentinel.backends.base import Backend, BackendError, Verdict, Verdicts
from sentinel.backends.fake import FakeBackend

__all__ = ["Backend", "BackendError", "Verdict", "Verdicts", "FakeBackend", "make_backend"]


def make_backend(kind: str, **kw):
    """Factory. kind: jev | claude | fake."""
    if kind == "jev":
        from sentinel.backends.jev import JevBackend

        return JevBackend(**kw)
    if kind == "claude":
        from sentinel.backends.claude import ClaudeSystemOneBackend

        return ClaudeSystemOneBackend(**kw)
    if kind == "fake":
        return FakeBackend(**kw)
    raise ValueError(f"unknown backend kind: {kind}")
