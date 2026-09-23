"""Cross-agent correlation (PRD section 10, last bullet).

Every existing open-source monitor scores one agent in isolation. The July
2026 incident was a fleet phenomenon: coordination scores rose across many
agents at once. This module keeps a rolling per-agent coordination score and
raises fleet severity when enough agents are rising together.

In-memory by default; `path` persists to sqlite so separate hook processes
(one per tool call, as in Claude Code) share the picture.
"""

from __future__ import annotations

import sqlite3
import math
import threading
import time
from collections import defaultdict, deque
from typing import Callable

from pydantic import BaseModel

from sentinel.backends.base import Verdicts

COORD_QUESTIONS = ("covert_channel", "encoding_for_peers", "coordination_mode", "peer_board")


class FleetSignal(BaseModel):
    agents_rising: int
    agents_seen: int
    mean_coordination: float
    boost: int          # rungs to escalate on the ladder
    note: str = ""


class Correlator:
    def __init__(self, rising_threshold: float = 0.5, min_agents: int = 3, window_s: float = 900.0, path: str | None = None,
                 *, clock: Callable[[], float] = time.time, max_future_skew_s: float = 30.0) -> None:
        if not math.isfinite(rising_threshold) or not 0 <= rising_threshold <= 1:
            raise ValueError("rising_threshold must be finite and in [0, 1]")
        if not math.isfinite(window_s) or window_s <= 0 or min_agents < 1:
            raise ValueError("window_s and min_agents must be positive")
        if not math.isfinite(max_future_skew_s) or max_future_skew_s < 0:
            raise ValueError("max_future_skew_s must be finite and nonnegative")
        self.rising_threshold = rising_threshold
        self.min_agents = min_agents
        self.window_s = window_s
        self._clock = clock
        self.max_future_skew_s = max_future_skew_s
        self._mem: dict[str, deque[tuple[float, float, float]]] = defaultdict(deque)
        self._lock = threading.Lock()
        self._db: sqlite3.Connection | None = None
        if path:
            self._db = sqlite3.connect(path, check_same_thread=False)
            # Serialize migration across hook processes. Existing evidence receives a
            # fresh retention period; its event timestamp is never used to delete it.
            self._db.execute("BEGIN IMMEDIATE")
            self._db.execute("CREATE TABLE IF NOT EXISTS coord (agent TEXT, ts REAL, score REAL, received_at REAL)")
            if "received_at" not in {row[1] for row in self._db.execute("PRAGMA table_info(coord)")}:
                self._db.execute("ALTER TABLE coord ADD COLUMN received_at REAL")
            self._db.execute("UPDATE coord SET received_at=? WHERE received_at IS NULL", (self._clock(),))
            self._db.execute("CREATE INDEX IF NOT EXISTS coord_ts ON coord(ts)")
            self._db.execute("CREATE INDEX IF NOT EXISTS coord_received_at ON coord(received_at)")
            self._db.commit()

    @staticmethod
    def coordination_score(verdicts: Verdicts | None, prefilter_hits: list[str]) -> float:
        best = 0.0
        if verdicts:
            for name in COORD_QUESTIONS:
                v = verdicts.get(name)
                if not v:
                    continue
                if v.kind == "noul":
                    best = max(best, v.probability)
                elif v.kind == "choice" and v.label and v.label not in ("none", "sanctioned"):
                    best = max(best, v.probability)
        if "peer_board" in prefilter_hits:
            best = max(best, 0.8)
        return best

    def record(self, agent_id: str, score: float, ts: float | None = None) -> FleetSignal:
        """Query event time, retain by trusted ingestion time (four windows).

        A host-supplied clock may be injected for replay. Agent timestamps cannot
        advance retention; events beyond the trusted clock's future skew are rejected.
        Late queries are necessarily limited to evidence still retained at ingestion.
        """
        received_at = self._clock()
        if not math.isfinite(received_at) or received_at < 0:
            raise ValueError("trusted clock must be finite and nonnegative")
        ts = received_at if ts is None else ts
        if not math.isfinite(ts) or ts < 0 or not math.isfinite(score) or not 0 <= score <= 1:
            raise ValueError("timestamp and coordination score must be finite and within bounds")
        if ts > received_at + self.max_future_skew_s:
            raise ValueError("event timestamp exceeds trusted clock's future skew")
        with self._lock:
            if self._db is not None:
                self._db.execute("INSERT INTO coord (agent, ts, score, received_at) VALUES (?,?,?,?)", (agent_id, ts, score, received_at))
                self._db.execute("DELETE FROM coord WHERE received_at < ?", (received_at - self.window_s * 4,))
                self._db.commit()
                rows = self._db.execute("SELECT agent, MAX(score) FROM coord WHERE ts >= ? AND ts <= ? GROUP BY agent", (ts - self.window_s, ts)).fetchall()
                latest = {a: s for a, s in rows}
            else:
                self._mem[agent_id].append((ts, score, received_at))
                for agent in list(self._mem):
                    retained = deque((t, s, r) for t, s, r in self._mem[agent] if r >= received_at - self.window_s * 4)
                    if retained:
                        self._mem[agent] = retained
                    else:
                        del self._mem[agent]
                latest = {}
                for a, dq in self._mem.items():
                    vals = [s for t, s, _ in dq if ts - self.window_s <= t <= ts]
                    if vals:
                        latest[a] = max(vals)
        return self.signal(latest)

    def signal(self, latest: dict[str, float]) -> FleetSignal:
        seen = len(latest)
        rising = sum(1 for s in latest.values() if s >= self.rising_threshold)
        mean = sum(latest.values()) / seen if seen else 0.0
        boost = 0
        note = ""
        if rising >= self.min_agents:
            boost = 1
            note = f"{rising}/{seen} agents show coordination >= {self.rising_threshold}"
            if rising >= 2 * self.min_agents or (seen > self.min_agents and rising / seen >= 0.5):
                boost = 2
                note += " (fleet-wide)"
        return FleetSignal(agents_rising=rising, agents_seen=seen, mean_coordination=round(mean, 3), boost=boost, note=note)


class DecisionStore:
    """Per-(agent, run) decision history shared across processes via sqlite.

    Claude Code runs one hook process per tool call; without this the
    slow-burn window never sees more than one step.
    """

    def __init__(self, path: str, keep: int = 64) -> None:
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.execute("CREATE TABLE IF NOT EXISTS decisions (agent TEXT, run TEXT, ts REAL, action INTEGER, own_signal INTEGER)")
        self._db.execute("CREATE INDEX IF NOT EXISTS decisions_key ON decisions(agent, run, ts)")
        self._db.commit()
        self.keep = keep

    def recent(self, agent: str, run: str, n: int) -> list[tuple[int, bool]]:
        rows = self._db.execute("SELECT action, own_signal FROM decisions WHERE agent=? AND run=? ORDER BY ts DESC LIMIT ?", (agent, run, n)).fetchall()
        return [(int(a), bool(o)) for a, o in reversed(rows)]

    def add(self, agent: str, run: str, ts: float, action: int, own_signal: bool) -> None:
        self._db.execute("INSERT INTO decisions VALUES (?,?,?,?,?)", (agent, run, ts, action, int(own_signal)))
        self._db.execute("DELETE FROM decisions WHERE rowid IN (SELECT rowid FROM decisions WHERE agent=? AND run=? ORDER BY ts DESC LIMIT -1 OFFSET ?)", (agent, run, self.keep))
        self._db.commit()
