"""Explicit operator credential-file loading; never source a shell script."""
from __future__ import annotations

import os
from pathlib import Path
import shlex
import stat
from collections.abc import Mapping
from typing import Literal

MONITOR_KEYS = frozenset({"TYPESAFE_API_KEY", "ANTHROPIC_API_KEY"})
PROVIDER_KEYS = MONITOR_KEYS | {"OPENAI_API_KEY"}


def provider_environment(credentials: Mapping[str, str], parent: Mapping[str, str]) -> dict[str, str]:
    """Copy an environment with exactly the explicitly selected provider secrets."""
    if set(credentials) - PROVIDER_KEYS:
        raise ValueError("only provider credentials may be supplied")
    return {**{k: v for k, v in parent.items() if k not in PROVIDER_KEYS}, **credentials}


def load_provider_credentials(path: str | Path, *, purpose: Literal["monitor", "openai_agent"] = "monitor") -> dict[str, str]:
    """Read a private, current-owner regular file containing literal export lines.

    No interpolation, command substitution, environment mutation or secret-bearing
    error messages. Callers decide which trusted child receives which provider key.
    """
    if purpose not in {"monitor", "openai_agent"}:
        raise ValueError("unknown credential purpose")
    allowed = MONITOR_KEYS if purpose == "monitor" else {"OPENAI_API_KEY"}
    fd = os.open(Path(path).expanduser(), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, encoding="utf-8") as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
            raise ValueError("credential file must be a private current-owner regular file")
        try:
            text = stream.read(16385)
        except UnicodeError:
            raise ValueError("invalid credential file encoding") from None
    if len(text) > 16384:
        raise ValueError("credential file is too large")
    result: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        try:
            parts = shlex.split(line, comments=True)
        except ValueError:
            raise ValueError("invalid literal credential export") from None
        if len(parts) != 2 or parts[0] != "export" or "=" not in parts[1]:
            raise ValueError("expected literal provider export lines")
        name, value = parts[1].split("=", 1)
        if name not in allowed or name in result or not value or any(c in value for c in "$`\r\n\x00"):
            raise ValueError("invalid provider credential entry")
        result[name] = value
    return result
