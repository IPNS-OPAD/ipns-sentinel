"""Invocation-bound, operator-owned peer snapshots for persistent MCP sessions."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import time

from pydantic import BaseModel, ConfigDict, Field


class TurnContext(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    agent_id: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    invocation_id: str = Field(min_length=1, max_length=128)
    peer_context: str = Field(max_length=2000)
    issued_at: float = Field(ge=0, allow_inf_nan=False)
    expires_at: float = Field(ge=0, allow_inf_nan=False)


def load_turn_context(directory: Path, *, agent_id: str, run_id: str, invocation_id: str) -> str:
    """Read one bounded private snapshot; no agent-controlled path components.

    The operator publishes the file before delivering its matching prompt. Each
    invocation uses a separate file, never a mutable 'current context' pointer.
    This trusts the operator filesystem, not other processes sharing its UID.
    """
    name = hashlib.sha256(invocation_id.encode()).hexdigest() + ".json"
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(fd)
        if metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
            raise ValueError("turn directory must be private and operator owned")
        child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        with os.fdopen(child, encoding="utf-8") as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
                raise ValueError("turn context must be a private operator-owned regular file")
            raw = stream.read(16385)
    finally:
        os.close(fd)
    if len(raw) > 16384:
        raise ValueError("turn context exceeds budget")
    context = TurnContext.model_validate_json(raw)
    now = time.time()
    if ((context.agent_id, context.run_id, context.invocation_id) != (agent_id, run_id, invocation_id)
            or not context.issued_at <= now < context.expires_at
            or not 0 < context.expires_at - context.issued_at <= 900):
        raise ValueError("turn context identity or lifetime mismatch")
    return context.peer_context
