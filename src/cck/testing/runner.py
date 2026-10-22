"""Scenario Runner and Failure Injection Engine for CCK Testing Lab (Layer 5).

Executes scenario definitions against isolated sandboxed control planes,
injects network faults, world mutations, and generates detailed test reports.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from cck.connectors.implementations.sandbox import InMemorySandboxConnector
from cck.testing.schema import ScenarioDefinition


class ScenarioResult(BaseModel):
    """Execution result report for a single test scenario."""

    scenario_id: str
    title: str
    passed: bool
    duration_ms: float
    error_message: str | None = None

    model_config = ConfigDict(extra="forbid")


class TestSuiteReport(BaseModel):
    """Aggregate summary report for a test suite run."""

    total: int = 0
    passed: int = 0
    failed: int = 0
    results: list[ScenarioResult] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = ConfigDict(extra="forbid")


class ScenarioRunner:
    """Loads and executes scenario test packs from disk or memory."""

    @staticmethod
    async def run_scenario_file(file_path: Path) -> ScenarioResult | None:
        """Load and run a JSON scenario file. Returns None if file is not a scenario definition."""
        start_time = datetime.now(timezone.utc)
        try:
            raw_data = json.loads(file_path.read_text(encoding="utf-8"))
            if not isinstance(raw_data, dict) or "scenario_id" not in raw_data or "steps" not in raw_data:
                return None  # Not a test scenario definition file

            scenario = ScenarioDefinition(**raw_data)
            connector = InMemorySandboxConnector()
            from cck.contracts.action import AgentAction, AgentIdentity
            from cck.core.types import ActionSeverity
            from cck.runtime.engine import CCKControlPlane

            control_plane = CCKControlPlane()
            await control_plane.initialize()

            try:
                for step in scenario.steps:
                    if step.action == "seed":
                        connector.seed_target(step.target, step.payload.get("data", {}), step.payload.get("version", 1))
                    elif step.action == "mutate_world":
                        connector.seed_target(step.target, step.payload.get("data", {}), step.payload.get("version", 2))
                    elif step.action == "inject_fault":
                        fault_type = step.payload.get("fault")
                        if fault_type == "timeout":
                            connector.simulate_timeout = True
                        elif fault_type == "disconnect_during":
                            connector.simulate_disconnect_during = True
                        elif fault_type == "auth_failure":
                            connector.simulate_auth_failure = True
                    elif step.action == "read":
                        read_res = await connector.read(step.target)
                        if step.payload.get("expected_data"):
                            for k, v in step.payload["expected_data"].items():
                                assert read_res.data.get(k) == v, f"Field mismatch: expected {k}={v}, got {read_res.data.get(k)}"
                    elif step.action == "execute":
                        action_data = step.payload.get("action", {})
                        action = AgentAction(
                            action_id=action_data.get("action_id", f"act-{scenario.scenario_id}"),
                            agent=AgentIdentity(
                                agent_id=action_data.get("agent_id", "test-agent"),
                                name=action_data.get("agent_name", "TestAgent"),
                                trust_tier=action_data.get("trust_tier", "standard"),
                            ),
                            session_id=f"sess-{scenario.scenario_id}",
                            capability=action_data.get("capability", "system.mutate"),
                            target=step.target,
                            parameters=action_data.get("parameters", {}),
                            severity=ActionSeverity(action_data.get("severity", "MUTATION")),
                        )
                        verdict = await control_plane.evaluate_action(action)
                        if step.expected_verdict:
                            expected = step.expected_verdict.upper()
                            actual = verdict.decision.value.upper()
                            if actual != expected:
                                raise ValueError(f"Verdict mismatch for step on {step.target}: expected {expected}, got {actual} ({verdict.reason})")
            finally:
                await control_plane.shutdown()

            duration = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000.0
            return ScenarioResult(
                scenario_id=scenario.scenario_id,
                title=scenario.title,
                passed=True,
                duration_ms=duration,
            )
        except Exception as exc:
            duration = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000.0
            return ScenarioResult(
                scenario_id=file_path.stem,
                title=file_path.name,
                passed=False,
                duration_ms=duration,
                error_message=str(exc),
            )

    @classmethod
    async def run_directory(cls, scenarios_dir: Path) -> TestSuiteReport:
        """Run all scenario JSON files in a directory."""
        report = TestSuiteReport()
        if not scenarios_dir.exists():
            return report

        for path in scenarios_dir.glob("*.json"):
            res = await cls.run_scenario_file(path)
            if res is not None:
                report.total += 1
                if res.passed:
                    report.passed += 1
                else:
                    report.failed += 1
                report.results.append(res)

        return report
