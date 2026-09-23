"""Declarative config (PRD section 14): backend, questions, thresholds, hooks, sinks."""

from __future__ import annotations

import os
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from sentinel.engine import Thresholds
from sentinel.state import PolicyContext


class ProviderConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)
    kind: Literal["jev", "claude", "fake"] = "fake"
    model: str | None = None
    timeout: float = Field(default=5.0, gt=0, allow_inf_nan=False)
    max_retries: int = Field(default=0, ge=0)
    effort: str = "low"                # claude only
    base_url: str | None = None        # claude only (gateway / on-prem)
    fallbacks: bool = True             # claude only: server-side refusal fallback (Claude API / Platform on AWS only)


class BackendConfig(ProviderConfig):
    fallback: Literal["jev", "claude", "fake"] | None = None
    fallback_config: ProviderConfig | None = None

    def primary_kwargs(self) -> dict[str, Any]:
        return self.model_dump(exclude={"kind", "fallback", "fallback_config"}, exclude_none=True)

    def secondary(self) -> ProviderConfig | None:
        return self.fallback_config or (ProviderConfig(kind=self.fallback) if self.fallback else None)


class CorrelationConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)
    enabled: bool = True
    rising_threshold: float = Field(default=0.5, ge=0, le=1, allow_inf_nan=False)
    min_agents: int = Field(default=3, ge=1)
    window_s: float = Field(default=900.0, gt=0, allow_inf_nan=False)
    max_future_skew_s: float = Field(default=30.0, ge=0, allow_inf_nan=False)
    path: str | None = None            # sqlite path for cross-process fleets


class SentinelConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)
    profile: Literal["development", "production"] = "development"
    backend: BackendConfig = Field(default_factory=BackendConfig)
    questions: list[str] | None = Field(default=None, min_length=1)
    question_bank: str | None = None              # YAML paraphrase bank (private in prod)
    thresholds: Thresholds = Field(default_factory=Thresholds)
    on_backend_error: Literal["open", "closed"] = "open"
    on_backend_refusal: Literal["pause", "open", "closed"] = "pause"
    min_action_to_alert: Literal["allow", "log", "warn", "pause", "kill"] = "warn"
    policy: PolicyContext = Field(default_factory=PolicyContext)
    correlation: CorrelationConfig = Field(default_factory=CorrelationConfig)
    audit_path: str = "~/.sentinel/audit.jsonl"
    audit_raw_inputs: bool = False                # True stores clipped raw tool inputs in the audit log; default is digests only
    alert_sinks: list[dict[str, Any]] = Field(default_factory=lambda: [{"type": "stderr"}])
    trajectory_window: int = Field(default=8, ge=1)
    state_max_chars: int = Field(default=6000, ge=1)

    @model_validator(mode="after")
    def validate_profile(self) -> "SentinelConfig":
        if self.questions is not None and len(set(self.questions)) != len(self.questions):
            raise ValueError("questions must have unique names")
        if self.backend.fallback_config and self.backend.fallback and self.backend.fallback_config.kind != self.backend.fallback:
            raise ValueError("fallback and fallback_config.kind must agree")
        if self.profile == "production":
            secondary = self.backend.secondary()
            if self.backend.kind == "fake" or (secondary is not None and secondary.kind == "fake"):
                raise ValueError("production profile requires real assessment providers")
            if self.on_backend_error != "closed" or self.on_backend_refusal == "open":
                raise ValueError("production profile requires closed failure and refusal policies")
            if not self.policy.task.strip():
                raise ValueError("production profile requires an operator-declared task")
            if self.correlation.enabled and not self.correlation.path:
                raise ValueError("production fleet correlation requires persistent storage")
        return self

    @classmethod
    def load(cls, path: str | None = None) -> "SentinelConfig":
        path = path or os.environ.get("SENTINEL_CONFIG")
        if not path:
            return cls()
        with open(os.path.expanduser(path)) as f:
            raw = yaml.safe_load(f) or {}
        return cls.model_validate(raw)
