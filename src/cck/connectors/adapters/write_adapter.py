"""Write Adapter for CCK Connectors.

Executes mutating actions strictly through a pathway routed via the CCK Action Gate,
Target Validator, and Idempotency Adapter, with zero secrets leaked in logs or journal.
"""

import time
from typing import Any

from cck.connectors.errors import normalize_connector_error
from cck.connectors.health import ConnectorHealthMonitor
from cck.connectors.idempotency import IdempotencyAdapter
from cck.connectors.interface import Connector, WriteResult
from cck.connectors.security import scrub_secrets
from cck.connectors.target_validator import TargetValidator
from cck.contracts.action import AgentAction
from cck.contracts.dependency import ActionDependencySpec
from cck.contracts.verdict import ExecutionVerdict
from cck.core.exceptions import (
    ActionGateError,
    TargetValidationError,
    UnknownExecutionOutcomeError,
)
from cck.core.logging import logger
from cck.core.types import IdempotencyStatus, JournalEventType, VerdictDecision
from cck.reliability.action_gate import ActionGate
from cck.reliability.journal import EventJournal


class WriteAdapter:
    """Dispatches external write actions strictly through the CCK governance pipeline."""

    def __init__(
        self,
        action_gate: ActionGate,
        target_validator: TargetValidator | None = None,
        idempotency_adapter: IdempotencyAdapter | None = None,
        event_journal: EventJournal | None = None,
        health_monitor: ConnectorHealthMonitor | None = None,
    ) -> None:
        self.action_gate = action_gate
        self.target_validator = target_validator or TargetValidator()
        self.idempotency_adapter = idempotency_adapter or IdempotencyAdapter()
        self.event_journal = event_journal
        self.health_monitor = health_monitor or ConnectorHealthMonitor()

    async def execute_write(
        self,
        connector: Connector,
        action: AgentAction,
        spec: ActionDependencySpec | None = None,
        expected_version: int | None = None,
        expected_target_values: dict[str, Any] | None = None,
        idempotency_key: str | None = None,
    ) -> WriteResult:
        """Execute a mutating write action through the CCK zero-bypass pipeline.

        Execution Pipeline:
        1. Sanitize & Log: Pre-flight payload with secret scrubbing.
        2. Gate Evaluation: Must receive VerdictDecision.ALLOW.
        3. Target Validation: Verify live target state and version matching.
        4. Idempotency Check: Return cached result if already completed.
        5. Connector Dispatch: Invoke external driver.
        6. Outcome Resolution: Handle disconnects and persist outcome.
        """
        idem_key = idempotency_key or action.idempotency_key
        scrubbed_params = scrub_secrets(action.parameters)
        logger.info(
            "WriteAdapter: Initiating action [%s] on connector [%s], target [%s]",
            action.action_id,
            connector.connector_id,
            action.target,
        )

        # 1. Zero-Bypass Gate Evaluation
        verdict: ExecutionVerdict = await self.action_gate.evaluate_action(action=action, spec=spec)
        if verdict.decision != VerdictDecision.ALLOW:
            self.health_monitor.record_policy_block(connector.connector_id)
            raise ActionGateError(
                f"Action '{action.action_id}' blocked by CCK ActionGate: {verdict.decision.value} - {verdict.reason}"
            )

        # 2. Target Precondition Validation
        await self.target_validator.validate_preconditions(
            connector=connector,
            target=action.target,
            expected_version=expected_version,
            expected_values=expected_target_values,
        )

        # 3. Idempotency Check
        if idem_key:
            existing_record = await self.idempotency_adapter.get_record(idem_key)
            if existing_record and existing_record.status == IdempotencyStatus.COMPLETED:
                logger.info("WriteAdapter: Idempotent replay for key [%s], returning cached result", idem_key)
                return WriteResult(
                    target=action.target,
                    success=True,
                    response_data=existing_record.result or {},
                )
            await self.idempotency_adapter.start_attempt(idem_key, action.action_id)

        # 4. Connector Dispatch
        start_time = time.monotonic()
        try:
            write_res = await connector.write(
                target=action.target,
                payload=action.parameters,
                expected_version=expected_version,
                idempotency_key=idem_key,
            )
            elapsed_ms = (time.monotonic() - start_time) * 1000.0

            # Record success
            self.health_monitor.record_success(connector.connector_id, elapsed_ms)
            if idem_key:
                await self.idempotency_adapter.complete_attempt(idem_key, write_res.response_data)

            # Record in journal with scrubbed secrets
            if self.event_journal:
                await self.event_journal.record_event(
                    correlation_id=action.session_id,
                    event_type=JournalEventType.ACTION_EXECUTED,
                    payload={
                        "action_id": action.action_id,
                        "connector_id": connector.connector_id,
                        "target": action.target,
                        "parameters": scrubbed_params,
                        "response": scrub_secrets(write_res.response_data),
                    },
                )

            return write_res

        except TargetValidationError:
            # Let domain target validation errors bubble cleanly
            raise

        except Exception as exc:
            elapsed_ms = (time.monotonic() - start_time) * 1000.0
            norm_err = normalize_connector_error(exc, connector_id=connector.connector_id)
            self.health_monitor.record_failure(connector.connector_id, elapsed_ms, str(norm_err))

            # Handle network disconnection / timeout after dispatch
            if norm_err.category in ("TIMEOUT", "CONNECTIVITY") and idem_key:
                await self.idempotency_adapter.mark_unknown_outcome(
                    idem_key,
                    error_msg=f"Disconnected during execution: {norm_err}",
                )
                raise UnknownExecutionOutcomeError(
                    f"Connection failed after dispatching action '{action.action_id}' to '{connector.connector_id}'. "
                    f"Outcome is UNKNOWN. Unsafe auto-retry prohibited!"
                ) from exc

            if idem_key:
                await self.idempotency_adapter.mark_failed(idem_key, str(norm_err))

            raise norm_err from exc
