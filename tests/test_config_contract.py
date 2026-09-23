import pytest
from pydantic import ValidationError

from sentinel.config import SentinelConfig
from sentinel.audit import AuditLog
from sentinel.observer import SentinelObserver


@pytest.mark.parametrize("values", [
    {"backend": {"timeout": 0}},
    {"backend": {"timeout": float("nan")}},
    {"correlation": {"window_s": 0}},
    {"thresholds": {"noul_critical": 2.0}},
    {"on_backend_error": "typo"},
    {"min_action_to_alert": "typo"},
    {"trajectory_window": 0},
    {"questions": []},
    {"unexpected_setting": True},
])
def test_invalid_configuration_is_rejected_at_load(values):
    with pytest.raises(ValidationError):
        SentinelConfig.model_validate(values)


def test_production_profile_rejects_development_defaults():
    with pytest.raises(ValidationError):
        SentinelConfig(profile="production")


def test_production_profile_requires_a_signed_audit_before_any_provider_call(tmp_path):
    cfg = SentinelConfig.model_validate({"profile": "production", "backend": {"kind": "jev"},
        "on_backend_error": "closed", "policy": {"task": "Run authorized tests"},
        "correlation": {"enabled": False}, "audit_path": str(tmp_path / "audit.jsonl")})
    with pytest.raises(ValueError, match="signed audit"):
        SentinelObserver(cfg, audit=AuditLog(cfg.audit_path, key=b"", warn_unsigned=False))
