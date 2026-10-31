-- Operation-bound approvals (specification 2.5, APR-001 to APR-005). An
-- approval names the operation instance it is for and its exact digest; it
-- does not depend on any executor table (MOD-004).
CREATE TABLE approvals (
    tenant           text        NOT NULL,
    id               text        NOT NULL,
    operation        text        NOT NULL,
    operation_digest text        NOT NULL,
    summary          jsonb       NOT NULL,
    requested_by     text        NOT NULL,
    actor            text        NOT NULL,
    state            text        NOT NULL,
    approver         text        NOT NULL DEFAULT '',
    expires_at       timestamptz NOT NULL,
    decided_at       timestamptz,
    consumed_at      timestamptz,
    PRIMARY KEY (tenant, id)
);
