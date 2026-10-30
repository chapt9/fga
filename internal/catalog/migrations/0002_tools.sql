-- Release R1-B: tools, agent keys, budgets, invocations, approvals and
-- reservations (specification 2.2, Part 2). As in 0001, every table is keyed
-- by tenant and references include the tenant.

-- API keys identify agents and approvers locally until identity providers
-- are decided (D-04). Only the SHA-256 of a key is stored.
CREATE TABLE agent_keys (
    key_hash   bytea       PRIMARY KEY,
    tenant     text        NOT NULL,
    identity   text        NOT NULL,
    revoked    boolean     NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant, identity) REFERENCES identities (tenant, id)
);

CREATE TABLE destinations (
    tenant          text   NOT NULL,
    id              text   NOT NULL,
    base_url        text   NOT NULL,
    allowed_cidrs   cidr[] NOT NULL,
    credential_file text   NOT NULL DEFAULT '',
    reconcile_path  text   NOT NULL DEFAULT '',
    PRIMARY KEY (tenant, id)
);

-- A tool is usable only while reviewed_digest equals the digest of its
-- record (AGT-001).
CREATE TABLE tools (
    tenant          text  NOT NULL,
    id              text  NOT NULL,
    record          jsonb NOT NULL,
    schema_digest   text  NOT NULL,
    reviewed_digest text  NOT NULL DEFAULT '',
    PRIMARY KEY (tenant, id)
);

-- Money is in integer minor units (DAT-005). The check makes overspending
-- impossible whatever the concurrency (APR-004).
CREATE TABLE budgets (
    tenant         text   NOT NULL,
    id             text   NOT NULL,
    currency       text   NOT NULL,
    limit_minor    bigint NOT NULL CHECK (limit_minor >= 0),
    reserved_minor bigint NOT NULL DEFAULT 0 CHECK (reserved_minor >= 0),
    spent_minor    bigint NOT NULL DEFAULT 0 CHECK (spent_minor >= 0),
    PRIMARY KEY (tenant, id),
    CHECK (reserved_minor + spent_minor <= limit_minor)
);

CREATE TABLE invocations (
    tenant           text        NOT NULL,
    id               text        NOT NULL,
    idempotency_key  text        NOT NULL,
    operation_digest text        NOT NULL,
    tool             text        NOT NULL,
    tool_version     int         NOT NULL,
    arguments        jsonb       NOT NULL,
    actor            text        NOT NULL,
    subject          text        NOT NULL DEFAULT '',
    delegation       text        NOT NULL DEFAULT '',
    state            text        NOT NULL,
    lease_owner      text        NOT NULL DEFAULT '',
    lease_expires_at timestamptz,
    fencing_token    bigint      NOT NULL DEFAULT 0,
    dispatched_at    timestamptz,
    receipt          text        NOT NULL DEFAULT '',
    resolution       jsonb,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant, id),
    UNIQUE (tenant, idempotency_key),
    FOREIGN KEY (tenant, tool) REFERENCES tools (tenant, id)
);

CREATE TABLE approvals (
    tenant           text        NOT NULL,
    id               text        NOT NULL,
    invocation       text        NOT NULL,
    operation_digest text        NOT NULL,
    summary          jsonb       NOT NULL,
    requested_by     text        NOT NULL,
    actor            text        NOT NULL,
    state            text        NOT NULL,
    approver         text        NOT NULL DEFAULT '',
    expires_at       timestamptz NOT NULL,
    decided_at       timestamptz,
    consumed_at      timestamptz,
    PRIMARY KEY (tenant, id),
    FOREIGN KEY (tenant, invocation) REFERENCES invocations (tenant, id)
);

CREATE TABLE reservations (
    tenant       text   NOT NULL,
    id           text   NOT NULL,
    budget       text   NOT NULL,
    invocation   text   NOT NULL,
    amount_minor bigint NOT NULL CHECK (amount_minor >= 0),
    state        text   NOT NULL,
    note         text   NOT NULL DEFAULT '',
    PRIMARY KEY (tenant, id),
    UNIQUE (tenant, invocation),
    FOREIGN KEY (tenant, budget)     REFERENCES budgets (tenant, id),
    FOREIGN KEY (tenant, invocation) REFERENCES invocations (tenant, id)
);
