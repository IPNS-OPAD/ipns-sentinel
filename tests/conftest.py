import os
import pytest

from sentinel.audit import AuditLog
from sentinel.backends.fake import FakeBackend
from sentinel.config import SentinelConfig
from sentinel.observer import SentinelObserver
from sentinel.state import PolicyContext

POLICY = PolicyContext(task="Fix a failing unit test and open a PR", allowed_scope=["repo", "git", "pytest"],
                       forbidden=["credential stores", "external uploads"], allowed_hosts=["github.com"], environment="test")


@pytest.fixture
def cfg(tmp_path):
    c = SentinelConfig()
    c.policy = POLICY
    c.audit_path = str(tmp_path / "audit.jsonl")
    c.correlation.enabled = False
    return c


@pytest.fixture
def observer(cfg, tmp_path):
    os.environ["SENTINEL_AUDIT_KEY"] = "test-key"
    return SentinelObserver(cfg, backend=FakeBackend(), sinks=[], audit=AuditLog(cfg.audit_path, key="test-key"))
