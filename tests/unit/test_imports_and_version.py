"""Tests confirming modular imports and packaging version integrity."""

import cck
import cck.api.app
import cck.audit.service
import cck.cli.main
import cck.contracts.action
import cck.contracts.audit
import cck.contracts.policy
import cck.contracts.verdict
import cck.core.config
import cck.core.exceptions
import cck.core.logging
import cck.core.types
import cck.policies.engine
import cck.runtime.engine
import cck.storage.base
import cck.storage.schema
import cck.storage.sqlite


def test_package_version() -> None:
    """Ensure root package exposes expected semantic version."""
    assert cck.__version__ == "0.1.0"


def test_core_exports() -> None:
    """Verify primary classes are exported cleanly at the top-level package namespace."""
    assert hasattr(cck, "AgentAction")
    assert hasattr(cck, "AgentIdentity")
    assert hasattr(cck, "ExecutionVerdict")
    assert hasattr(cck, "PolicyRule")
    assert hasattr(cck, "AuditRecord")
    assert hasattr(cck, "CCKControlPlane")
    assert hasattr(cck, "SQLiteStorageBackend")
    assert hasattr(cck, "VerdictDecision")
    assert hasattr(cck, "RiskLevel")
