-- Recipient public keys (specification 2.5, RCP-001, RCP-002, RES-009).
-- Only public keys are stored; a key resolves a recipient check only while
-- ACTIVE, and every status change advances the revision (authority fence,
-- step 5).
CREATE TABLE recipient_keys (
    tenant      text        NOT NULL,
    fingerprint text        NOT NULL,
    principal   text        NOT NULL,
    public_key  bytea       NOT NULL,
    suite       integer     NOT NULL,
    key_version bigint      NOT NULL,
    status      text        NOT NULL CHECK (status IN ('PENDING', 'ACTIVE', 'REVOKED')),
    revision    bigint      NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant, fingerprint),
    UNIQUE (tenant, principal, key_version),
    FOREIGN KEY (tenant, principal) REFERENCES identities (tenant, id)
);
