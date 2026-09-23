"""Decision engine (PRD section 10): thresholds, escalation ladder, window aggregation."""

from __future__ import annotations

import time
from uuid import uuid4
from enum import IntEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from sentinel.backends.base import Verdicts
from sentinel.prefilter import PrefilterHit
from sentinel.questions import QuestionSpec


class Action(IntEnum):
    ALLOW = 0
    LOG = 1
    WARN = 2
    PAUSE = 3
    KILL = 4

    @property
    def label(self) -> str:
        return self.name.lower()


class Thresholds(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)
    noul_critical: float = Field(default=0.70, ge=0, le=1, allow_inf_nan=False)
    noul_high: float = Field(default=0.75, ge=0, le=1, allow_inf_nan=False)
    noul_suspicious: float = Field(default=0.50, ge=0, le=1, allow_inf_nan=False)
    score_pause: float = Field(default=4.0, ge=0, allow_inf_nan=False)
    score_suspicious: float = Field(default=2.5, ge=0, allow_inf_nan=False)
    choice_min_confidence: float = Field(default=0.60, ge=0, le=1, allow_inf_nan=False)
    multi_signal_count: int = Field(default=2, ge=1)
    window_steps: int = Field(default=5, ge=1)
    window_suspicious_steps: int = Field(default=3, ge=1)
    kill_on_critical_count: int = Field(default=2, ge=1)


class Trigger(BaseModel):
    name: str
    kind: str
    severity: str
    threat_class: str
    value: float
    label: str | None = None
    source: str = "model"   # model | prefilter | correlation


class Decision(BaseModel):
    decision_id: str = Field(default_factory=lambda: str(uuid4()))
    invocation_id: str | None = None
    fleet_boost: int = 0
    action: Action
    severity: str = "none"
    triggers: list[Trigger] = Field(default_factory=list)
    reason: str = ""
    fail_mode: str | None = None    # "open" | "closed" when the backend failed
    assessment_status: str = "complete"
    own_signal: bool = False        # this step had its own triggers (not just a ladder escalation)
    verdicts: Verdicts | None = None
    prefilter: list[PrefilterHit] = Field(default_factory=list)
    ts: float = Field(default_factory=time.time)

    @property
    def blocks(self) -> bool:
        return self.action >= Action.PAUSE


class DecisionEngine:
    def __init__(self, thresholds: Thresholds | None = None, on_backend_error: str = "open", on_backend_refusal: str = "pause") -> None:
        self.t = thresholds or Thresholds()
        if on_backend_error not in ("open", "closed"):
            raise ValueError("on_backend_error must be 'open' or 'closed'")
        if on_backend_refusal not in ("pause", "open", "closed"):
            raise ValueError("on_backend_refusal must be 'pause', 'open' or 'closed'")
        self.on_backend_error = on_backend_error
        self.on_backend_refusal = on_backend_refusal

    # --- scoring -------------------------------------------------------------
    def score(self, verdicts: Verdicts | None, questions: list[QuestionSpec], prefilter: list[PrefilterHit],
              history: list[Decision] | None = None, correlation_boost: int = 0, backend_failed: bool = False,
              backend_refused: bool = False, input_incomplete: bool = False) -> Decision:
        t = self.t
        triggers: list[Trigger] = []
        hard_block = False

        for h in prefilter:
            triggers.append(Trigger(name=h.rule_id, kind="rule", severity="critical" if h.on == "block" else "suspicious",
                                    threat_class=h.threat_class, value=1.0, source="prefilter"))
            hard_block = hard_block or h.on == "block"

        if verdicts is not None:
            table = {q.name: q for q in questions}
            for name, v in verdicts.items.items():
                q = table.get(name)
                if not q:
                    continue
                if v.kind == "noul":
                    thr = {"critical": t.noul_critical, "high": t.noul_high}.get(q.severity, t.noul_suspicious)
                    if v.probability >= thr:
                        triggers.append(Trigger(name=name, kind="noul", severity=q.severity, threat_class=q.threat_class, value=v.probability))
                    elif v.probability >= t.noul_suspicious:
                        triggers.append(Trigger(name=name, kind="noul", severity="suspicious", threat_class=q.threat_class, value=v.probability))
                elif v.kind == "choice":
                    if v.label in q.hit_labels and v.probability >= t.choice_min_confidence:
                        triggers.append(Trigger(name=name, kind="choice", severity=q.label_severity.get(v.label, q.severity),
                                                threat_class=q.threat_class, value=v.probability, label=v.label))
                elif v.kind == "score" and v.score is not None:
                    if v.score >= t.score_pause:
                        triggers.append(Trigger(name=name, kind="score", severity=q.severity, threat_class=q.threat_class, value=v.score))
                    elif v.score >= t.score_suspicious:
                        triggers.append(Trigger(name=name, kind="score", severity="suspicious", threat_class=q.threat_class, value=v.score))

        crit = [x for x in triggers if x.severity == "critical"]
        high = [x for x in triggers if x.severity == "high"]
        susp = [x for x in triggers if x.severity == "suspicious"]

        # ladder: allow -> log -> warn -> pause -> kill
        if hard_block or len(crit) >= t.kill_on_critical_count:
            action = Action.KILL
        elif crit or high:
            action = Action.PAUSE
        elif len(susp) >= t.multi_signal_count:
            action = Action.WARN
        elif susp:
            action = Action.LOG
        else:
            action = Action.ALLOW

        # slow-burn: repeated steps with their OWN signals inside the window escalate one rung.
        # Escalated-but-clean steps do not count, so the ladder cannot ratchet on itself.
        own_signal = bool(triggers)
        recent = (history or [])[-(t.window_steps - 1):] if t.window_steps > 1 else []
        suspicious_steps = sum(1 for d in recent if d.own_signal) + (1 if own_signal else 0)
        if own_signal and action < Action.KILL and suspicious_steps >= t.window_suspicious_steps:
            action = Action(min(action + 1, Action.KILL))

        # fleet correlation escalates by the number of rungs the correlator asks for
        if correlation_boost:
            action = Action(min(action + correlation_boost, Action.KILL))

        fail_mode = None
        if backend_refused and verdicts is None:
            fail_mode = f"refusal:{self.on_backend_refusal}"
            if self.on_backend_refusal in ("pause", "closed") and action < Action.PAUSE:
                action = Action.PAUSE
                triggers.append(Trigger(name="backend_refusal", kind="system", severity="high", threat_class="general", value=1.0, source="system"))
        elif backend_failed and verdicts is None:
            fail_mode = self.on_backend_error
            if self.on_backend_error == "closed" and action < Action.PAUSE:
                action = Action.PAUSE
                triggers.append(Trigger(name="backend_unavailable", kind="system", severity="high", threat_class="general", value=1.0, source="system"))

        if input_incomplete:
            action = max(action, Action.PAUSE)
            triggers.append(Trigger(name="incomplete_action", kind="system", severity="high", threat_class="general", value=1.0, source="system"))

        severity = "critical" if crit or action == Action.KILL else "high" if high or action == Action.PAUSE else "suspicious" if susp else "none"
        reason = self._reason(action, triggers, fail_mode, correlation_boost)
        return Decision(action=action, severity=severity, triggers=triggers, reason=reason, fail_mode=fail_mode,
                        verdicts=verdicts, prefilter=prefilter, own_signal=own_signal)

    @staticmethod
    def _reason(action: Action, triggers: list[Trigger], fail_mode: str | None, boost: int) -> str:
        if not triggers and action == Action.ALLOW:
            return "no signals"
        parts = [f"{x.name}={x.value:.2f}" + (f"[{x.label}]" if x.label else "") for x in sorted(triggers, key=lambda x: -x.value)[:6]]
        s = f"{action.label}: " + ", ".join(parts)
        if boost:
            s += f"; fleet correlation +{boost}"
        if fail_mode:
            s += f"; backend failed ({fail_mode})"
        return s
