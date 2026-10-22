import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import aiosqlite

from cck.contracts.action import AgentAction
from cck.contracts.audit import AuditRecord
from cck.contracts.entity import Entity
from cck.contracts.evidence import Evidence
from cck.contracts.fact import Fact
from cck.contracts.journal import JournalEntry
from cck.contracts.policy import PolicyRule
from cck.core.exceptions import StorageError
from cck.core.logging import logger
from cck.policies.engine import DEFAULT_BASELINE_POLICIES
from cck.storage.base import StorageBackend
from cck.storage.schema import SQLITE_SCHEMA_DDL


class SQLiteStorageBackend(StorageBackend):
    """Production-grade asynchronous SQLite storage backend for local development & testing."""

    def __init__(self, db_path: Path | str = "./cck.db") -> None:
        self.db_path = Path(db_path)
        self._connection: aiosqlite.Connection | None = None

    async def _get_conn(self) -> aiosqlite.Connection:
        if self._connection is None:
            # Ensure parent directories exist
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self._connection = await aiosqlite.connect(str(self.db_path))
            self._connection.row_factory = aiosqlite.Row
            await self._connection.execute("PRAGMA journal_mode = WAL;")
            await self._connection.execute("PRAGMA foreign_keys = ON;")
            await self._connection.commit()
        return self._connection

    async def initialize(self) -> None:
        """Execute DDL schema migrations and seed initial defaults."""
        try:
            conn = await self._get_conn()
            await conn.executescript(SQLITE_SCHEMA_DDL)
            await conn.commit()

            # Seed baseline policies if empty
            async with conn.execute("SELECT COUNT(*) AS cnt FROM cck_policies;") as cur:
                row = await cur.fetchone()
                if row and row["cnt"] == 0:
                    for pol in DEFAULT_BASELINE_POLICIES:
                        await self.save_policy(pol)
                    logger.info("Seeded %d baseline security policies", len(DEFAULT_BASELINE_POLICIES))

            # Seed default cloud projects if empty
            async with conn.execute("SELECT COUNT(*) AS cnt FROM cck_projects;") as cur:
                row = await cur.fetchone()
                if row and row["cnt"] == 0:
                    now = datetime.now(timezone.utc).isoformat()
                    await conn.execute(
                        """
                        INSERT INTO cck_projects (project_id, name, tenant_id, description, connectors_json, rate_limit_per_minute, active_agents, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                        """,
                        ("proj-default", "Production Guardrails", "tenant-corp-acme", "Autonomous warehouse shipment and dispatch agents", json.dumps(["in_memory_sandbox"]), 5000, 12, now),
                    )
                    await conn.execute(
                        """
                        INSERT INTO cck_projects (project_id, name, tenant_id, description, connectors_json, rate_limit_per_minute, active_agents, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                        """,
                        ("proj-staging", "Staging Sandbox Agents", "tenant-corp-acme", "DevOps and patch management automated worker bots", json.dumps(["in_memory_sandbox"]), 1000, 5, now),
                    )
                    await conn.commit()

            # Seed default admin user if empty
            async with conn.execute("SELECT COUNT(*) AS cnt FROM cck_users;") as cur:
                row = await cur.fetchone()
                if row and row["cnt"] == 0:
                    now = datetime.now(timezone.utc).isoformat()
                    pwd_hash = hashlib.sha256(b"admin123456").hexdigest()
                    await conn.execute(
                        """
                        INSERT INTO cck_users (user_id, username, password_hash, display_name, role, tenant_id, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?);
                        """,
                        ("usr-admin-01", "admin", pwd_hash, "Security Operator", "admin", "tenant-corp-acme", now),
                    )
                    await conn.commit()

            # Seed sample pending approval if empty
            async with conn.execute("SELECT COUNT(*) AS cnt FROM cck_approvals;") as cur:
                row = await cur.fetchone()
                if row and row["cnt"] == 0:
                    now = datetime.now(timezone.utc).isoformat()
                    await conn.execute(
                        """
                        INSERT INTO cck_approvals (approval_id, action_id, agent_id, capability, target, command, reason, status, state_snapshot_json, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                        """,
                        (
                            "appr-001",
                            "act-scale-prod-99",
                            "agt-auto-scaler",
                            "kubernetes.scale",
                            "deployment/api-core",
                            "kubectl scale deployment/api-core --replicas=20",
                            "زيادة عدد الحاويات تتجاوز حد التكلفة التشغيلية التلقائية ($500/hr)",
                            "PENDING",
                            json.dumps({"replicas": 5, "target_replicas": 20, "estimated_hourly_cost": 650.0}),
                            now,
                        ),
                    )
                    await conn.commit()

            # Seed default API keys if empty
            async with conn.execute("SELECT COUNT(*) AS cnt FROM cck_api_keys;") as cur:
                row = await cur.fetchone()
                if row and row["cnt"] == 0:
                    now = datetime.now(timezone.utc).isoformat()
                    key_hash = hashlib.sha256(b"cck_live_prod_secret_token_12345").hexdigest()
                    await conn.execute(
                        """
                        INSERT INTO cck_api_keys (key_id, project_id, name, key_prefix, key_hash, created_at, is_active)
                        VALUES (?, ?, ?, ?, ?, ?, 1);
                        """,
                        ("key-prod-01", "proj-default", "Production Agent Service Key", "cck_live_prod...", key_hash, now),
                    )
                    await conn.commit()

            # Seed default facts & evidence if empty
            async with conn.execute("SELECT COUNT(*) AS cnt FROM cck_facts;") as cur:
                row = await cur.fetchone()
                if row and row["cnt"] == 0:
                    now = datetime.now(timezone.utc).isoformat()
                    # Evidence
                    await conn.execute(
                        """
                        INSERT INTO cck_evidence (evidence_id, entity_id, field_name, raw_payload_json, source, observed_at, payload_hash)
                        VALUES (?, ?, ?, ?, ?, ?, ?);
                        """,
                        (
                            "evi-order-1099-01",
                            "order:1099",
                            "status",
                            json.dumps({"order_id": "1099", "payment_status": "captured", "amount": 149.0}),
                            "stripe_webhook",
                            now,
                            hashlib.sha256(b"order_1099_paid").hexdigest(),
                        ),
                    )
                    # Fact
                    await conn.execute(
                        """
                        INSERT INTO cck_facts (entity_id, field_name, value_json, source, observed_at, version, state, evidence_id, ttl_seconds, field_fingerprint)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                        """,
                        (
                            "order:1099",
                            "status",
                            json.dumps("paid"),
                            "stripe_webhook",
                            now,
                            1,
                            "VALID",
                            "evi-order-1099-01",
                            300.0,
                            hashlib.sha256(b"order:1099.status=paid").hexdigest(),
                        ),
                    )
                    # Dependencies
                    await conn.execute(
                        """
                        INSERT INTO cck_dependencies (dep_id, project_id, action_capability, required_fact_entity, required_fact_field, max_age_seconds, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?);
                        """,
                        (
                            "dep-ship-order-status",
                            "proj-default",
                            "logistics.ship",
                            "order:1099",
                            "status",
                            300.0,
                            now,
                        ),
                    )
                    await conn.commit()

            logger.info("SQLite schema initialized successfully at %s", self.db_path)
        except Exception as exc:
            logger.error("Failed to initialize SQLite storage: %s", exc)
            raise StorageError(f"Database initialization failed: {exc}") from exc

    async def close(self) -> None:
        """Close database connection."""
        if self._connection is not None:
            await self._connection.close()
            self._connection = None

    # Actions
    async def save_action(self, action: AgentAction) -> None:
        """Store an agent action."""
        try:
            conn = await self._get_conn()
            payload_json = action.model_dump_json()
            await conn.execute(
                """
                INSERT OR REPLACE INTO cck_actions (
                    action_id, agent_id, session_id, capability,
                    target, severity, idempotency_key, payload_json, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    action.action_id,
                    action.agent.agent_id,
                    action.session_id,
                    action.capability,
                    action.target,
                    action.severity.value,
                    action.idempotency_key,
                    payload_json,
                    action.timestamp.isoformat(),
                ),
            )
            await conn.commit()
        except Exception as exc:
            raise StorageError(f"Failed to save action {action.action_id}: {exc}") from exc

    async def get_action(self, action_id: str) -> AgentAction | None:
        """Fetch an action by ID."""
        try:
            conn = await self._get_conn()
            async with conn.execute(
                "SELECT payload_json FROM cck_actions WHERE action_id = ?;",
                (action_id,),
            ) as cursor:
                row = await cursor.fetchone()
                if not row:
                    return None
                return AgentAction.model_validate_json(row["payload_json"])
        except Exception as exc:
            raise StorageError(f"Failed to fetch action {action_id}: {exc}") from exc

    # Policies
    async def save_policy(self, policy: PolicyRule) -> None:
        """Store or update a policy rule."""
        try:
            conn = await self._get_conn()
            conditions_json = json.dumps(policy.conditions)
            await conn.execute(
                """
                INSERT OR REPLACE INTO cck_policies (
                    rule_id, name, description, capability_pattern,
                    target_pattern, action_effect, risk_level, is_active, conditions_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    policy.rule_id,
                    policy.name,
                    policy.description,
                    policy.capability_pattern,
                    policy.target_pattern,
                    policy.action_effect.value,
                    policy.risk_level.value,
                    1 if policy.is_active else 0,
                    conditions_json,
                ),
            )
            await conn.commit()
        except Exception as exc:
            raise StorageError(f"Failed to save policy {policy.rule_id}: {exc}") from exc

    async def get_policy(self, rule_id: str) -> PolicyRule | None:
        """Fetch policy rule by ID."""
        try:
            conn = await self._get_conn()
            async with conn.execute(
                """
                SELECT rule_id, name, description, capability_pattern,
                       target_pattern, action_effect, risk_level, is_active, conditions_json
                FROM cck_policies WHERE rule_id = ?;
                """,
                (rule_id,),
            ) as cursor:
                row = await cursor.fetchone()
                if not row:
                    return None
                return PolicyRule(
                    rule_id=row["rule_id"],
                    name=row["name"],
                    description=row["description"],
                    capability_pattern=row["capability_pattern"],
                    target_pattern=row["target_pattern"],
                    action_effect=row["action_effect"],
                    risk_level=row["risk_level"],
                    is_active=bool(row["is_active"]),
                    conditions=json.loads(row["conditions_json"]),
                )
        except Exception as exc:
            raise StorageError(f"Failed to fetch policy {rule_id}: {exc}") from exc

    async def list_policies(self, active_only: bool = True) -> list[PolicyRule]:
        """List policy rules."""
        try:
            conn = await self._get_conn()
            query = "SELECT rule_id, name, description, capability_pattern, target_pattern, action_effect, risk_level, is_active, conditions_json FROM cck_policies"
            params: tuple = ()
            if active_only:
                query += " WHERE is_active = 1"

            async with conn.execute(query, params) as cursor:
                rows = await cursor.fetchall()
                return [
                    PolicyRule(
                        rule_id=row["rule_id"],
                        name=row["name"],
                        description=row["description"],
                        capability_pattern=row["capability_pattern"],
                        target_pattern=row["target_pattern"],
                        action_effect=row["action_effect"],
                        risk_level=row["risk_level"],
                        is_active=bool(row["is_active"]),
                        conditions=json.loads(row["conditions_json"]),
                    )
                    for row in rows
                ]
        except Exception as exc:
            raise StorageError(f"Failed to list policies: {exc}") from exc

    # Audits
    async def record_audit(self, audit: AuditRecord) -> None:
        """Append an audit record to the ledger."""
        try:
            conn = await self._get_conn()
            verdict_json = audit.verdict.model_dump_json()
            result_json = json.dumps(audit.execution_result) if audit.execution_result else None

            await conn.execute(
                """
                INSERT INTO cck_audits (
                    audit_id, action_id, agent_id, action_hash,
                    previous_hash, verdict_json, execution_status,
                    execution_result_json, recorded_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    audit.audit_id,
                    audit.action_id,
                    audit.agent_id,
                    audit.action_hash,
                    audit.previous_hash,
                    verdict_json,
                    audit.execution_status.value,
                    result_json,
                    audit.recorded_at.isoformat(),
                ),
            )
            await conn.commit()
        except Exception as exc:
            raise StorageError(f"Failed to record audit entry {audit.audit_id}: {exc}") from exc

    async def list_audits(self, limit: int = 50, offset: int = 0) -> list[AuditRecord]:
        """Retrieve paginated audit entries."""
        try:
            conn = await self._get_conn()
            async with conn.execute(
                """
                SELECT audit_id, action_id, agent_id, action_hash,
                       previous_hash, verdict_json, execution_status,
                       execution_result_json, recorded_at
                FROM cck_audits ORDER BY recorded_at DESC LIMIT ? OFFSET ?;
                """,
                (limit, offset),
            ) as cursor:
                rows = await cursor.fetchall()
                results: list[AuditRecord] = []
                for row in rows:
                    results.append(
                        AuditRecord(
                            audit_id=row["audit_id"],
                            action_id=row["action_id"],
                            agent_id=row["agent_id"],
                            action_hash=row["action_hash"],
                            previous_hash=row["previous_hash"],
                            verdict=json.loads(row["verdict_json"]),
                            execution_status=row["execution_status"],
                            execution_result=json.loads(row["execution_result_json"])
                            if row["execution_result_json"]
                            else None,
                            recorded_at=row["recorded_at"],
                        )
                    )
                return results
        except Exception as exc:
            raise StorageError(f"Failed to list audits: {exc}") from exc

    async def get_last_audit_hash(self) -> str | None:
        """Fetch the action_hash of the newest audit entry."""
        try:
            conn = await self._get_conn()
            async with conn.execute(
                "SELECT action_hash FROM cck_audits ORDER BY rowid DESC LIMIT 1;"
            ) as cursor:
                row = await cursor.fetchone()
                return row["action_hash"] if row else None
        except Exception as exc:
            raise StorageError(f"Failed to fetch last audit hash: {exc}") from exc

    # Entities
    async def save_entity(self, entity: Entity) -> None:
        """Store or update an entity."""
        try:
            conn = await self._get_conn()
            attributes_json = json.dumps(entity.attributes)
            await conn.execute(
                """
                INSERT OR REPLACE INTO cck_entities (
                    entity_id, entity_type, name, attributes_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?);
                """,
                (
                    entity.entity_id,
                    entity.entity_type,
                    entity.name,
                    attributes_json,
                    entity.created_at.isoformat(),
                    entity.updated_at.isoformat(),
                ),
            )
            await conn.commit()
        except Exception as exc:
            raise StorageError(f"Failed to save entity {entity.entity_id}: {exc}") from exc

    async def get_entity(self, entity_id: str) -> Entity | None:
        """Fetch an entity by ID."""
        try:
            conn = await self._get_conn()
            async with conn.execute(
                "SELECT entity_id, entity_type, name, attributes_json, created_at, updated_at FROM cck_entities WHERE entity_id = ?;",
                (entity_id,),
            ) as cursor:
                row = await cursor.fetchone()
                if not row:
                    return None
                return Entity(
                    entity_id=row["entity_id"],
                    entity_type=row["entity_type"],
                    name=row["name"],
                    attributes=json.loads(row["attributes_json"]),
                    created_at=row["created_at"],
                    updated_at=row["updated_at"],
                )
        except Exception as exc:
            raise StorageError(f"Failed to fetch entity {entity_id}: {exc}") from exc

    async def list_entities(self, entity_type: str | None = None) -> list[Entity]:
        """List entities."""
        try:
            conn = await self._get_conn()
            query = "SELECT entity_id, entity_type, name, attributes_json, created_at, updated_at FROM cck_entities"
            params: tuple = ()
            if entity_type:
                query += " WHERE entity_type = ?"
                params = (entity_type,)

            async with conn.execute(query, params) as cursor:
                rows = await cursor.fetchall()
                return [
                    Entity(
                        entity_id=row["entity_id"],
                        entity_type=row["entity_type"],
                        name=row["name"],
                        attributes=json.loads(row["attributes_json"]),
                        created_at=row["created_at"],
                        updated_at=row["updated_at"],
                    )
                    for row in rows
                ]
        except Exception as exc:
            raise StorageError(f"Failed to list entities: {exc}") from exc

    # Facts
    async def save_fact(self, fact: Fact) -> None:
        """Store or update a fact."""
        try:
            conn = await self._get_conn()
            value_json = json.dumps(fact.value)
            await conn.execute(
                """
                INSERT OR REPLACE INTO cck_facts (
                    entity_id, field_name, value_json, source,
                    observed_at, version, state, evidence_id, ttl_seconds, field_fingerprint
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    fact.entity_id,
                    fact.field_name,
                    value_json,
                    fact.source,
                    fact.observed_at.isoformat(),
                    fact.version,
                    fact.state.value,
                    fact.evidence_id,
                    fact.ttl_seconds,
                    fact.field_fingerprint,
                ),
            )
            await conn.commit()
        except Exception as exc:
            raise StorageError(f"Failed to save fact {fact.entity_id}.{fact.field_name}: {exc}") from exc

    async def get_fact(self, entity_id: str, field_name: str) -> Fact | None:
        """Fetch a specific fact."""
        try:
            conn = await self._get_conn()
            async with conn.execute(
                """
                SELECT entity_id, field_name, value_json, source,
                       observed_at, version, state, evidence_id, ttl_seconds, field_fingerprint
                FROM cck_facts WHERE entity_id = ? AND field_name = ?;
                """,
                (entity_id, field_name),
            ) as cursor:
                row = await cursor.fetchone()
                if not row:
                    return None
                return Fact(
                    entity_id=row["entity_id"],
                    field_name=row["field_name"],
                    value=json.loads(row["value_json"]),
                    source=row["source"],
                    observed_at=row["observed_at"],
                    version=row["version"],
                    state=row["state"],
                    evidence_id=row["evidence_id"],
                    ttl_seconds=row["ttl_seconds"],
                    field_fingerprint=row["field_fingerprint"],
                )
        except Exception as exc:
            raise StorageError(f"Failed to fetch fact {entity_id}.{field_name}: {exc}") from exc

    async def list_facts_for_entity(self, entity_id: str) -> list[Fact]:
        """Fetch all facts attached to an entity."""
        try:
            conn = await self._get_conn()
            async with conn.execute(
                """
                SELECT entity_id, field_name, value_json, source,
                       observed_at, version, state, evidence_id, ttl_seconds, field_fingerprint
                FROM cck_facts WHERE entity_id = ?;
                """,
                (entity_id,),
            ) as cursor:
                rows = await cursor.fetchall()
                return [
                    Fact(
                        entity_id=row["entity_id"],
                        field_name=row["field_name"],
                        value=json.loads(row["value_json"]),
                        source=row["source"],
                        observed_at=row["observed_at"],
                        version=row["version"],
                        state=row["state"],
                        evidence_id=row["evidence_id"],
                        ttl_seconds=row["ttl_seconds"],
                        field_fingerprint=row["field_fingerprint"],
                    )
                    for row in rows
                ]
        except Exception as exc:
            raise StorageError(f"Failed to list facts for entity {entity_id}: {exc}") from exc

    # Evidence
    async def save_evidence(self, evidence: Evidence) -> None:
        """Store an evidence record."""
        try:
            conn = await self._get_conn()
            raw_payload_json = json.dumps(evidence.raw_payload)
            metadata_json = json.dumps(evidence.metadata)
            await conn.execute(
                """
                INSERT OR REPLACE INTO cck_evidence (
                    evidence_id, entity_id, field_name, raw_payload_json,
                    source, observed_at, payload_hash, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    evidence.evidence_id,
                    evidence.entity_id,
                    evidence.field_name,
                    raw_payload_json,
                    evidence.source,
                    evidence.observed_at.isoformat(),
                    evidence.payload_hash,
                    metadata_json,
                ),
            )
            await conn.commit()
        except Exception as exc:
            raise StorageError(f"Failed to save evidence {evidence.evidence_id}: {exc}") from exc

    async def get_evidence(self, evidence_id: str) -> Evidence | None:
        """Fetch evidence by ID."""
        try:
            conn = await self._get_conn()
            async with conn.execute(
                """
                SELECT evidence_id, entity_id, field_name, raw_payload_json,
                       source, observed_at, payload_hash, metadata_json
                FROM cck_evidence WHERE evidence_id = ?;
                """,
                (evidence_id,),
            ) as cursor:
                row = await cursor.fetchone()
                if not row:
                    return None
                return Evidence(
                    evidence_id=row["evidence_id"],
                    entity_id=row["entity_id"],
                    field_name=row["field_name"],
                    raw_payload=json.loads(row["raw_payload_json"]),
                    source=row["source"],
                    observed_at=row["observed_at"],
                    payload_hash=row["payload_hash"],
                    metadata=json.loads(row["metadata_json"]),
                )
        except Exception as exc:
            raise StorageError(f"Failed to fetch evidence {evidence_id}: {exc}") from exc

    # Event Journal
    async def append_journal(self, entry: JournalEntry) -> None:
        """Append an event to the journal."""
        try:
            conn = await self._get_conn()
            payload_json = json.dumps(entry.payload)
            await conn.execute(
                """
                INSERT INTO cck_journal (
                    entry_id, timestamp, correlation_id, event_type,
                    policy_version, payload_json, previous_hash, entry_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    entry.entry_id,
                    entry.timestamp.isoformat(),
                    entry.correlation_id,
                    entry.event_type.value,
                    entry.policy_version,
                    payload_json,
                    entry.previous_hash,
                    entry.entry_hash,
                ),
            )
            await conn.commit()
        except Exception as exc:
            raise StorageError(f"Failed to append journal entry {entry.entry_id}: {exc}") from exc

    async def list_journal_entries(
        self,
        correlation_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[JournalEntry]:
        """List journal entries ordered by timestamp asc."""
        try:
            conn = await self._get_conn()
            query = "SELECT entry_id, timestamp, correlation_id, event_type, policy_version, payload_json, previous_hash, entry_hash FROM cck_journal"
            params: list = []
            if correlation_id:
                query += " WHERE correlation_id = ?"
                params.append(correlation_id)
            query += " ORDER BY rowid ASC LIMIT ? OFFSET ?"
            params.extend([limit, offset])

            async with conn.execute(query, tuple(params)) as cursor:
                rows = await cursor.fetchall()
                return [
                    JournalEntry(
                        entry_id=row["entry_id"],
                        timestamp=row["timestamp"],
                        correlation_id=row["correlation_id"],
                        event_type=row["event_type"],
                        policy_version=row["policy_version"],
                        payload=json.loads(row["payload_json"]),
                        previous_hash=row["previous_hash"],
                        entry_hash=row["entry_hash"],
                    )
                    for row in rows
                ]
        except Exception as exc:
            raise StorageError(f"Failed to list journal entries: {exc}") from exc

    async def get_last_journal_hash(self) -> str | None:
        """Get the hash of the newest journal entry."""
        try:
            conn = await self._get_conn()
            async with conn.execute(
                "SELECT entry_hash FROM cck_journal ORDER BY rowid DESC LIMIT 1;"
            ) as cursor:
                row = await cursor.fetchone()
                return row["entry_hash"] if row else None
        except Exception as exc:
            raise StorageError(f"Failed to fetch last journal hash: {exc}") from exc

    # Projects (Tenancy)
    async def list_projects(self, tenant_id: str | None = None) -> list[dict]:
        """List tenant projects."""
        try:
            conn = await self._get_conn()
            query = "SELECT project_id, name, tenant_id, description, connectors_json, rate_limit_per_minute, active_agents, created_at FROM cck_projects"
            params: list = []
            if tenant_id:
                query += " WHERE tenant_id = ?"
                params.append(tenant_id)
            query += " ORDER BY created_at DESC"
            async with conn.execute(query, tuple(params)) as cursor:
                rows = await cursor.fetchall()
                return [
                    {
                        "project_id": row["project_id"],
                        "name": row["name"],
                        "tenant_id": row["tenant_id"],
                        "description": row["description"],
                        "connectors": json.loads(row["connectors_json"]),
                        "rate_limit_per_minute": row["rate_limit_per_minute"],
                        "active_agents": row["active_agents"],
                        "created_at": row["created_at"],
                    }
                    for row in rows
                ]
        except Exception as exc:
            raise StorageError(f"Failed to list projects: {exc}") from exc

    async def save_project(self, project: dict) -> None:
        """Store or update a tenant project."""
        try:
            conn = await self._get_conn()
            now = project.get("created_at") or datetime.now(timezone.utc).isoformat()
            connectors = project.get("connectors", ["in_memory_sandbox"])
            await conn.execute(
                """
                INSERT OR REPLACE INTO cck_projects (
                    project_id, name, tenant_id, description, connectors_json,
                    rate_limit_per_minute, active_agents, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    project["project_id"],
                    project["name"],
                    project.get("tenant_id", "tenant-corp-acme"),
                    project.get("description", ""),
                    json.dumps(connectors),
                    project.get("rate_limit_per_minute", 1000),
                    project.get("active_agents", 1),
                    now,
                ),
            )
            await conn.commit()
        except Exception as exc:
            raise StorageError(f"Failed to save project: {exc}") from exc

    async def delete_project(self, project_id: str) -> bool:
        """Delete a project by ID."""
        try:
            conn = await self._get_conn()
            cursor = await conn.execute(
                "DELETE FROM cck_projects WHERE project_id = ?;",
                (project_id,),
            )
            await conn.commit()
            return cursor.rowcount > 0
        except Exception as exc:
            raise StorageError(f"Failed to delete project {project_id}: {exc}") from exc

    # Users & Auth
    async def get_user_by_username(self, username: str) -> dict | None:
        """Fetch user by username."""
        try:
            conn = await self._get_conn()
            async with conn.execute(
                "SELECT user_id, username, password_hash, display_name, role, tenant_id, created_at FROM cck_users WHERE username = ?;",
                (username,),
            ) as cursor:
                row = await cursor.fetchone()
                if not row:
                    return None
                return dict(row)
        except Exception as exc:
            raise StorageError(f"Failed to fetch user {username}: {exc}") from exc

    async def save_user(self, user: dict) -> None:
        """Register or update a system user."""
        try:
            conn = await self._get_conn()
            now = user.get("created_at") or datetime.now(timezone.utc).isoformat()
            await conn.execute(
                """
                INSERT OR REPLACE INTO cck_users (
                    user_id, username, password_hash, display_name, role, tenant_id, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    user["user_id"],
                    user["username"],
                    user["password_hash"],
                    user["display_name"],
                    user.get("role", "operator"),
                    user.get("tenant_id", "tenant-corp-acme"),
                    now,
                ),
            )
            await conn.commit()
        except Exception as exc:
            raise StorageError(f"Failed to save user: {exc}") from exc

    # Approvals Queue
    async def list_approvals(self, status: str | None = None) -> list[dict]:
        """List human approval requests."""
        try:
            conn = await self._get_conn()
            query = "SELECT approval_id, action_id, agent_id, capability, target, command, reason, status, state_snapshot_json, reviewer, reviewer_notes, created_at, resolved_at FROM cck_approvals"
            params: list = []
            if status:
                query += " WHERE status = ?"
                params.append(status)
            query += " ORDER BY created_at DESC"
            async with conn.execute(query, tuple(params)) as cursor:
                rows = await cursor.fetchall()
                return [
                    {
                        "approval_id": row["approval_id"],
                        "action_id": row["action_id"],
                        "agent_id": row["agent_id"],
                        "capability": row["capability"],
                        "target": row["target"],
                        "command": row["command"],
                        "reason": row["reason"],
                        "status": row["status"],
                        "state_snapshot": json.loads(row["state_snapshot_json"]),
                        "reviewer": row["reviewer"],
                        "reviewer_notes": row["reviewer_notes"],
                        "created_at": row["created_at"],
                        "resolved_at": row["resolved_at"],
                    }
                    for row in rows
                ]
        except Exception as exc:
            raise StorageError(f"Failed to list approvals: {exc}") from exc

    async def save_approval(self, approval: dict) -> None:
        """Save a pending approval request."""
        try:
            conn = await self._get_conn()
            now = approval.get("created_at") or datetime.now(timezone.utc).isoformat()
            snapshot = approval.get("state_snapshot", {})
            await conn.execute(
                """
                INSERT OR REPLACE INTO cck_approvals (
                    approval_id, action_id, agent_id, capability, target, command,
                    reason, status, state_snapshot_json, reviewer, reviewer_notes, created_at, resolved_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    approval["approval_id"],
                    approval["action_id"],
                    approval["agent_id"],
                    approval["capability"],
                    approval["target"],
                    approval["command"],
                    approval["reason"],
                    approval.get("status", "PENDING"),
                    json.dumps(snapshot),
                    approval.get("reviewer"),
                    approval.get("reviewer_notes"),
                    now,
                    approval.get("resolved_at"),
                ),
            )
            await conn.commit()
        except Exception as exc:
            raise StorageError(f"Failed to save approval: {exc}") from exc

    async def resolve_approval(self, approval_id: str, approved: bool, reviewer: str = "operator", notes: str = "") -> dict | None:
        """Resolve a pending approval request."""
        try:
            conn = await self._get_conn()
            now = datetime.now(timezone.utc).isoformat()
            new_status = "APPROVED" if approved else "REJECTED"
            cursor = await conn.execute(
                """
                UPDATE cck_approvals
                SET status = ?, reviewer = ?, reviewer_notes = ?, resolved_at = ?
                WHERE approval_id = ?;
                """,
                (new_status, reviewer, notes, now, approval_id),
            )
            await conn.commit()
            if cursor.rowcount == 0:
                return None
            return {
                "approval_id": approval_id,
                "status": new_status,
                "reviewer": reviewer,
                "notes": notes,
                "resolved_at": now,
            }
        except Exception as exc:
            raise StorageError(f"Failed to resolve approval: {exc}") from exc

    # Facts & Evidence Bulk Listing
    async def list_all_facts(self) -> list[dict]:
        """Fetch all stored facts across all entities."""
        try:
            conn = await self._get_conn()
            async with conn.execute(
                """
                SELECT entity_id, field_name, value_json, source,
                       observed_at, version, state, evidence_id, ttl_seconds, field_fingerprint
                FROM cck_facts ORDER BY observed_at DESC;
                """
            ) as cursor:
                rows = await cursor.fetchall()
                return [
                    {
                        "entity_id": row["entity_id"],
                        "field_name": row["field_name"],
                        "value": json.loads(row["value_json"]),
                        "source": row["source"],
                        "observed_at": row["observed_at"],
                        "version": row["version"],
                        "state": row["state"],
                        "evidence_id": row["evidence_id"],
                        "ttl_seconds": row["ttl_seconds"],
                        "field_fingerprint": row["field_fingerprint"],
                    }
                    for row in rows
                ]
        except Exception as exc:
            raise StorageError(f"Failed to list all facts: {exc}") from exc

    async def list_all_evidence(self) -> list[dict]:
        """Fetch all stored evidence entries."""
        try:
            conn = await self._get_conn()
            async with conn.execute(
                """
                SELECT evidence_id, entity_id, field_name, raw_payload_json,
                       source, observed_at, payload_hash, metadata_json
                FROM cck_evidence ORDER BY observed_at DESC;
                """
            ) as cursor:
                rows = await cursor.fetchall()
                return [
                    {
                        "evidence_id": row["evidence_id"],
                        "entity_id": row["entity_id"],
                        "field_name": row["field_name"],
                        "raw_payload": json.loads(row["raw_payload_json"]),
                        "source": row["source"],
                        "observed_at": row["observed_at"],
                        "payload_hash": row["payload_hash"],
                        "metadata": json.loads(row["metadata_json"]),
                    }
                    for row in rows
                ]
        except Exception as exc:
            raise StorageError(f"Failed to list all evidence: {exc}") from exc

    # API Keys Management
    async def list_api_keys(self, project_id: str | None = None) -> list[dict]:
        """List active and revoked API keys."""
        try:
            conn = await self._get_conn()
            query = "SELECT key_id, project_id, name, key_prefix, key_hash, created_at, expires_at, is_active FROM cck_api_keys"
            params: list = []
            if project_id:
                query += " WHERE project_id = ?"
                params.append(project_id)
            query += " ORDER BY created_at DESC;"
            async with conn.execute(query, tuple(params)) as cursor:
                rows = await cursor.fetchall()
                return [
                    {
                        "key_id": row["key_id"],
                        "project_id": row["project_id"],
                        "name": row["name"],
                        "key_prefix": row["key_prefix"],
                        "created_at": row["created_at"],
                        "expires_at": row["expires_at"],
                        "is_active": bool(row["is_active"]),
                    }
                    for row in rows
                ]
        except Exception as exc:
            raise StorageError(f"Failed to list API keys: {exc}") from exc

    async def save_api_key(self, key_data: dict) -> None:
        """Store a new hashed API key."""
        try:
            conn = await self._get_conn()
            await conn.execute(
                """
                INSERT INTO cck_api_keys (key_id, project_id, name, key_prefix, key_hash, created_at, is_active)
                VALUES (?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    key_data["key_id"],
                    key_data["project_id"],
                    key_data["name"],
                    key_data["key_prefix"],
                    key_data["key_hash"],
                    key_data.get("created_at") or datetime.now(timezone.utc).isoformat(),
                    1 if key_data.get("is_active", True) else 0,
                ),
            )
            await conn.commit()
        except Exception as exc:
            raise StorageError(f"Failed to save API key: {exc}") from exc

    async def revoke_api_key(self, key_id: str) -> bool:
        """Revoke an API key."""
        try:
            conn = await self._get_conn()
            cursor = await conn.execute(
                "UPDATE cck_api_keys SET is_active = 0 WHERE key_id = ?;",
                (key_id,),
            )
            await conn.commit()
            return cursor.rowcount > 0
        except Exception as exc:
            raise StorageError(f"Failed to revoke API key {key_id}: {exc}") from exc

    # Dependencies
    async def list_dependencies(self, project_id: str | None = None) -> list[dict]:
        """List action-to-fact dependency graph specifications."""
        try:
            conn = await self._get_conn()
            query = "SELECT dep_id, project_id, action_capability, required_fact_entity, required_fact_field, max_age_seconds, created_at FROM cck_dependencies"
            params: list = []
            if project_id:
                query += " WHERE project_id = ?"
                params.append(project_id)
            query += " ORDER BY created_at DESC;"
            async with conn.execute(query, tuple(params)) as cursor:
                rows = await cursor.fetchall()
                return [
                    {
                        "dep_id": row["dep_id"],
                        "project_id": row["project_id"],
                        "action_capability": row["action_capability"],
                        "required_fact_entity": row["required_fact_entity"],
                        "required_fact_field": row["required_fact_field"],
                        "max_age_seconds": row["max_age_seconds"],
                        "created_at": row["created_at"],
                    }
                    for row in rows
                ]
        except Exception as exc:
            raise StorageError(f"Failed to list dependencies: {exc}") from exc

    async def save_dependency(self, dep: dict) -> None:
        """Save a dependency specification rule."""
        try:
            conn = await self._get_conn()
            await conn.execute(
                """
                INSERT OR REPLACE INTO cck_dependencies (
                    dep_id, project_id, action_capability, required_fact_entity,
                    required_fact_field, max_age_seconds, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    dep["dep_id"],
                    dep.get("project_id", "proj-default"),
                    dep["action_capability"],
                    dep["required_fact_entity"],
                    dep["required_fact_field"],
                    dep.get("max_age_seconds", 300.0),
                    dep.get("created_at") or datetime.now(timezone.utc).isoformat(),
                ),
            )
            await conn.commit()
        except Exception as exc:
            raise StorageError(f"Failed to save dependency: {exc}") from exc

    async def delete_dependency(self, dep_id: str) -> bool:
        """Delete a dependency specification rule."""
        try:
            conn = await self._get_conn()
            cursor = await conn.execute(
                "DELETE FROM cck_dependencies WHERE dep_id = ?;",
                (dep_id,),
            )
            await conn.commit()
            return cursor.rowcount > 0
        except Exception as exc:
            raise StorageError(f"Failed to delete dependency {dep_id}: {exc}") from exc


