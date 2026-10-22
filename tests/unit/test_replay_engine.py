"""Unit tests for Replay Engine."""

from datetime import datetime, timezone

import pytest

from cck.contracts.action import AgentAction, AgentIdentity
from cck.contracts.dependency import ActionDependencySpec
from cck.contracts.journal import JournalEntry
from cck.core.types import ActionSeverity, JournalEventType, VerdictDecision
from cck.reliability.replay_engine import ReplayEngine


@pytest.mark.asyncio
async def test_replay_engine_reproduces_verdict_with_zero_external_execution() -> None:
    """Replaying a session reproduces identical decision and guarantees ZERO external actions executed."""
    engine = ReplayEngine()
    now = datetime(2026, 10, 18, 12, 0, 0, tzinfo=timezone.utc)

    agent = AgentIdentity(agent_id="agt-rep", name="ReplayBot")
    action = AgentAction(
        action_id="act-rep-01",
        agent=agent,
        session_id="sess-rep",
        capability="filesystem.read",
        target="/var/log/syslog",
        severity=ActionSeverity.INFORMATIONAL,
    )
    spec = ActionDependencySpec(
        action_id=action.action_id,
        decision_id="dec-rep-01",
        required_facts=[],
        claimed_evidence_ids=[],
    )

    # Recorded journal events
    entries = [
        JournalEntry(
            entry_id="j1",
            timestamp=now,
            correlation_id="sess-rep",
            event_type=JournalEventType.FACT_OBSERVED,
            policy_version="1.0.0",
            payload={
                "entity_id": "sys:node",
                "field_name": "load",
                "value": "low",
                "source": "monitor",
            },
        ),
        JournalEntry(
            entry_id="j2",
            timestamp=now,
            correlation_id="sess-rep",
            event_type=JournalEventType.GATE_DECISION,
            policy_version="1.0.0",
            payload={
                "action": action.model_dump(mode="json"),
                "spec": spec.model_dump(mode="json"),
                "decision": VerdictDecision.ALLOW.value,
            },
        ),
        JournalEntry(
            entry_id="j3",
            timestamp=now,
            correlation_id="sess-rep",
            event_type=JournalEventType.ACTION_EXECUTED,
            policy_version="1.0.0",
            payload={"action_id": action.action_id, "status": "executed"},
        ),
    ]

    report = await engine.replay_session(journal_entries=entries, expected_policy_version="1.0.0")

    # Critical constraints verification
    assert report.is_fully_reproducible is True
    assert report.total_steps == 3
    assert report.matched_steps == 3
    assert report.divergent_steps == 0
    # ZERO external actions executed!
    assert report.external_actions_executed == 0


@pytest.mark.asyncio
async def test_replay_divergence_on_policy_version_mismatch() -> None:
    """Replaying with an incompatible policy version flags divergence."""
    engine = ReplayEngine()
    now = datetime(2026, 10, 18, 12, 0, 0, tzinfo=timezone.utc)

    entries = [
        JournalEntry(
            entry_id="j-old",
            timestamp=now,
            correlation_id="sess-old",
            event_type=JournalEventType.FACT_OBSERVED,
            policy_version="0.9.0",  # Old policy version
            payload={"entity_id": "order:1", "field_name": "status", "value": "paid", "source": "db"},
        )
    ]

    report = await engine.replay_session(journal_entries=entries, expected_policy_version="2.0.0")
    assert report.is_fully_reproducible is False
    assert report.divergent_steps == 1
    assert "Policy version mismatch" in report.divergence_details[0]
