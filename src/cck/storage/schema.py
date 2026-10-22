"""Schema definitions, DDL, and migrations for CCK storage."""

# Canonical SQLite DDL
SQLITE_SCHEMA_DDL = """
-- Agent actions log
CREATE TABLE IF NOT EXISTS cck_actions (
    action_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    capability TEXT NOT NULL,
    target TEXT NOT NULL,
    severity TEXT NOT NULL,
    idempotency_key TEXT,
    payload_json TEXT NOT NULL,
    timestamp TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_actions_agent ON cck_actions(agent_id);
CREATE INDEX IF NOT EXISTS idx_actions_session ON cck_actions(session_id);
CREATE INDEX IF NOT EXISTS idx_actions_timestamp ON cck_actions(timestamp);
CREATE INDEX IF NOT EXISTS idx_actions_idempotency ON cck_actions(idempotency_key);

-- Governance and security policies
CREATE TABLE IF NOT EXISTS cck_policies (
    rule_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    capability_pattern TEXT NOT NULL,
    target_pattern TEXT NOT NULL,
    action_effect TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1,
    conditions_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_policies_active ON cck_policies(is_active);

-- Tamper-evident immutable audit log
CREATE TABLE IF NOT EXISTS cck_audits (
    audit_id TEXT PRIMARY KEY,
    action_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    action_hash TEXT NOT NULL,
    previous_hash TEXT,
    verdict_json TEXT NOT NULL,
    execution_status TEXT NOT NULL,
    execution_result_json TEXT,
    recorded_at TEXT NOT NULL,
    FOREIGN KEY(action_id) REFERENCES cck_actions(action_id)
);

CREATE INDEX IF NOT EXISTS idx_audits_action ON cck_audits(action_id);
CREATE INDEX IF NOT EXISTS idx_audits_agent ON cck_audits(agent_id);
CREATE INDEX IF NOT EXISTS idx_audits_recorded_at ON cck_audits(recorded_at);

-- Entity Identity Registry
CREATE TABLE IF NOT EXISTS cck_entities (
    entity_id TEXT PRIMARY KEY,
    entity_type TEXT NOT NULL,
    name TEXT NOT NULL,
    attributes_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_entities_type ON cck_entities(entity_type);
CREATE INDEX IF NOT EXISTS idx_entities_name ON cck_entities(name);

-- Fact Registry
CREATE TABLE IF NOT EXISTS cck_facts (
    entity_id TEXT NOT NULL,
    field_name TEXT NOT NULL,
    value_json TEXT NOT NULL,
    source TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    state TEXT NOT NULL,
    evidence_id TEXT,
    ttl_seconds REAL,
    field_fingerprint TEXT NOT NULL,
    PRIMARY KEY (entity_id, field_name)
);

CREATE INDEX IF NOT EXISTS idx_facts_state ON cck_facts(state);
CREATE INDEX IF NOT EXISTS idx_facts_observed ON cck_facts(observed_at);

-- Evidence Registry
CREATE TABLE IF NOT EXISTS cck_evidence (
    evidence_id TEXT PRIMARY KEY,
    entity_id TEXT NOT NULL,
    field_name TEXT NOT NULL,
    raw_payload_json TEXT NOT NULL,
    source TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_evidence_entity ON cck_evidence(entity_id);
CREATE INDEX IF NOT EXISTS idx_evidence_hash ON cck_evidence(payload_hash);

-- Event Journal
CREATE TABLE IF NOT EXISTS cck_journal (
    entry_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    correlation_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    previous_hash TEXT,
    entry_hash TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_journal_timestamp ON cck_journal(timestamp);
CREATE INDEX IF NOT EXISTS idx_journal_correlation ON cck_journal(correlation_id);
CREATE INDEX IF NOT EXISTS idx_journal_event_type ON cck_journal(event_type);

-- Projects & Tenant Spaces
CREATE TABLE IF NOT EXISTS cck_projects (
    project_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    connectors_json TEXT NOT NULL DEFAULT '["in_memory_sandbox"]',
    rate_limit_per_minute INTEGER NOT NULL DEFAULT 1000,
    active_agents INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_projects_tenant ON cck_projects(tenant_id);

-- System Users & Role-Based Auth
CREATE TABLE IF NOT EXISTS cck_users (
    user_id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'operator',
    tenant_id TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_users_username ON cck_users(username);

-- Human Review Approvals Queue
CREATE TABLE IF NOT EXISTS cck_approvals (
    approval_id TEXT PRIMARY KEY,
    action_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    capability TEXT NOT NULL,
    target TEXT NOT NULL,
    command TEXT NOT NULL,
    reason TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING',
    state_snapshot_json TEXT NOT NULL DEFAULT '{}',
    reviewer TEXT,
    reviewer_notes TEXT,
    created_at TEXT NOT NULL,
    resolved_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_approvals_status ON cck_approvals(status);

-- Project API Keys
CREATE TABLE IF NOT EXISTS cck_api_keys (
    key_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    name TEXT NOT NULL,
    key_prefix TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT,
    is_active INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_api_keys_project ON cck_api_keys(project_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON cck_api_keys(key_hash);

-- Action Dependency Graphs & Specifications
CREATE TABLE IF NOT EXISTS cck_dependencies (
    dep_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    action_capability TEXT NOT NULL,
    required_fact_entity TEXT NOT NULL,
    required_fact_field TEXT NOT NULL,
    max_age_seconds REAL DEFAULT 300.0,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_deps_project ON cck_dependencies(project_id);
CREATE INDEX IF NOT EXISTS idx_deps_capability ON cck_dependencies(action_capability);
"""

# Reference mapping for PostgreSQL production migrations
POSTGRESQL_TYPE_MAPPING = {
    "TEXT PRIMARY KEY": "VARCHAR(128) PRIMARY KEY",
    "INTEGER NOT NULL DEFAULT 1": "BOOLEAN NOT NULL DEFAULT TRUE",
    "payload_json TEXT": "payload JSONB",
    "conditions_json TEXT": "conditions JSONB",
    "verdict_json TEXT": "verdict JSONB",
    "attributes_json TEXT": "attributes JSONB",
    "value_json TEXT": "value JSONB",
    "raw_payload_json TEXT": "raw_payload JSONB",
    "metadata_json TEXT": "metadata JSONB",
    "execution_result_json TEXT": "execution_result JSONB",
    "timestamp TEXT": "timestamp TIMESTAMPTZ NOT NULL",
    "recorded_at TEXT": "recorded_at TIMESTAMPTZ NOT NULL",
    "observed_at TEXT": "observed_at TIMESTAMPTZ NOT NULL",
}
