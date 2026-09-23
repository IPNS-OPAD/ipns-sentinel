"""Tamper-evident audit log: append-only JSONL, hash-chained, HMAC-signed.

Each record carries a sequence number, the previous record's hash, and an
HMAC over (prev_hash || canonical payload) keyed by SENTINEL_AUDIT_KEY (or
the contents of SENTINEL_AUDIT_KEY_FILE). A signed *head* file beside the
log records the latest (seq, hash), so truncating or dropping the tail is
detected as well as editing the middle.

What `verify()` detects without the key: edits, reorders, chain breaks,
unparseable lines, truncation while the head file survives, and a head
file that went missing at any point (the next append records a permanent
`+head_missing` marker instead of silently re-deriving the head).
Without an independently retained checkpoint it cannot detect deleting BOTH
the log and the head file, or a rewrite by a party holding the key. A trusted
checkpoint anchors only its prefix; it says nothing about an unanchored tail.
Keep the key away from the agent
(separate OS user, or a remote sink) and the head file on a different
write path in production. This is documented in DECISIONS D5.
"""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Iterator
from pydantic import BaseModel, ConfigDict, Field

GENESIS = "0" * 64


class AuditCheckpoint(BaseModel):
    """A trusted prefix anchor. Store outside the log writer's authority."""
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    seq: int = Field(ge=1)
    hash: str = Field(pattern=r"^[0-9a-f]{64}$")


def _canon(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode()


def _load_key(key: bytes | str | None) -> bytes:
    if key is not None:
        return key.encode() if isinstance(key, str) else key
    k = os.environ.get("SENTINEL_AUDIT_KEY", "")
    if not k and os.environ.get("SENTINEL_AUDIT_KEY_FILE"):
        try:
            k = Path(os.environ["SENTINEL_AUDIT_KEY_FILE"]).read_text().strip()
        except OSError:
            k = ""
    return k.encode()


class AuditLog:
    def __init__(self, path: str | os.PathLike[str], key: bytes | str | None = None, warn_unsigned: bool = True) -> None:
        self.path = Path(path)
        self.head_path = self.path.with_suffix(self.path.suffix + ".head")
        self.key = _load_key(key)
        self.unsigned = not self.key
        if self.unsigned and warn_unsigned:
            print("[sentinel] WARNING: audit log is UNSIGNED (set SENTINEL_AUDIT_KEY or SENTINEL_AUDIT_KEY_FILE)", file=sys.stderr)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    # --- head file -----------------------------------------------------------
    def _sign(self, body: bytes) -> str | None:
        return hmac.new(self.key, body, hashlib.sha256).hexdigest() if self.key else None

    def _read_head(self) -> dict[str, Any] | None:
        try:
            return json.loads(self.head_path.read_text())
        except (OSError, json.JSONDecodeError):
            return None

    def _write_head(self, seq: int, h: str) -> None:
        body = _canon({"seq": seq, "hash": h})
        tmp = self.head_path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"seq": seq, "hash": h, "sig": self._sign(body)}))
        os.replace(tmp, self.head_path)

    def _tail(self) -> tuple[int, str]:
        """(seq, hash) of the last parseable record, or (0, GENESIS)."""
        if not self.path.exists() or self.path.stat().st_size == 0:
            return 0, GENESIS
        with self.path.open("rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            back = min(size, 65536)
            f.seek(size - back)
            lines = f.read().splitlines()
        for line in reversed(lines):
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
                return int(rec["seq"]), rec["hash"]
            except (json.JSONDecodeError, KeyError, ValueError, TypeError):
                continue
        return 0, GENESIS

    # --- API ---------------------------------------------------------------
    def append(self, kind: str, payload: dict[str, Any]) -> dict[str, Any]:
        with self.path.open("a") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                head = self._read_head()
                seq, prev = (int(head["seq"]), head["hash"]) if head else self._tail()
                degraded = head is None and seq > 0   # log exists but head is gone: possible truncation
                seq += 1
                if degraded:
                    payload = {**payload, "_head_missing_before_seq": seq}
                    kind = f"{kind}+head_missing"
                rec: dict[str, Any] = {"seq": seq, "ts": time.time(), "kind": kind, "prev": prev, "payload": payload}
                body = prev.encode() + _canon({"seq": seq, "ts": rec["ts"], "kind": kind, "payload": payload})
                rec["hash"] = hashlib.sha256(body).hexdigest()
                rec["sig"] = self._sign(body)
                f.write(json.dumps(rec, default=str) + "\n")
                f.flush()
                self._write_head(seq, rec["hash"])
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        return rec

    def records(self) -> Iterator[dict[str, Any]]:
        if not self.path.exists():
            return iter(())
        out = []
        with self.path.open() as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    out.append({"_unparseable": line[:80]})
        return iter(out)

    def checkpoint(self) -> AuditCheckpoint:
        """Export a verified prefix, not an independent witness or remote upload.

        The caller must preserve this value separately from the broker/log/key.
        Holding the normal writer lock prevents a concurrent honest append while
        the verified snapshot is exported. Empty/unsigned logs cannot be anchored.
        """
        if self.unsigned or not self.path.exists():
            raise ValueError("checkpoint requires a nonempty signed audit")
        with self.path.open() as stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_SH)
            try:
                ok, message = self.verify()
                if not ok:
                    raise ValueError("cannot checkpoint invalid audit: " + message)
                head = self._read_head()
                if not head:
                    raise ValueError("checkpoint requires a nonempty signed audit")
                return AuditCheckpoint(seq=head["seq"], hash=head["hash"])
            finally:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)

    def verify(self, *, checkpoint: AuditCheckpoint | None = None) -> tuple[bool, str]:
        prev, seq, n = GENESIS, 0, 0
        anchor_seen = checkpoint is None
        for rec in self.records():
            n += 1
            if "_unparseable" in rec:
                return False, f"record {n}: unparseable line"
            if rec.get("seq") != seq + 1:
                return False, f"record {n}: sequence break (expected {seq + 1}, got {rec.get('seq')})"
            if rec.get("prev") != prev:
                return False, f"record {n}: chain break"
            body = prev.encode() + _canon({"seq": rec["seq"], "ts": rec["ts"], "kind": rec["kind"], "payload": rec["payload"]})
            if hashlib.sha256(body).hexdigest() != rec.get("hash"):
                return False, f"record {n}: hash mismatch"
            if self.key and not (rec.get("sig") and hmac.compare_digest(rec["sig"], self._sign(body) or "")):
                return False, f"record {n}: bad signature"
            prev, seq = rec["hash"], rec["seq"]
            if checkpoint is not None and seq == checkpoint.seq:
                if not hmac.compare_digest(prev, checkpoint.hash):
                    return False, "independent checkpoint: prefix hash mismatch"
                anchor_seen = True
        if not anchor_seen:
            return False, "independent checkpoint: anchored prefix is missing"
        for rec in self.records():
            if isinstance(rec.get("kind"), str) and rec["kind"].endswith("+head_missing"):
                return False, f"record {rec.get('seq')}: head file was missing before this append; earlier truncation cannot be ruled out"
        head = self._read_head()
        if head is None:
            if n:
                return False, "head file missing: cannot rule out truncation"
        else:
            hb = _canon({"seq": head.get("seq"), "hash": head.get("hash")})
            if self.key and not (head.get("sig") and hmac.compare_digest(head["sig"], self._sign(hb) or "")):
                return False, "head file: bad signature"
            if head.get("seq") != seq or head.get("hash") != prev:
                return False, f"truncated: head says seq {head.get('seq')}, log ends at {seq}"
        return True, f"{n} records ok" + (" (UNSIGNED)" if not self.key else "")
