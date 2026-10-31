-- Self-service content-signing keys (RCP-002): a key is PENDING from its
-- enrollment until a possession proof answers its one-use challenge.
ALTER TABLE signing_keys DROP CONSTRAINT signing_keys_status_check;
ALTER TABLE signing_keys ADD CONSTRAINT signing_keys_status_check
    CHECK (status IN ('PENDING', 'ACTIVE', 'RETIRED', 'COMPROMISED'));

CREATE TABLE signing_challenges (
    tenant      text        NOT NULL,
    id          uuid        NOT NULL,
    principal   text        NOT NULL,
    fingerprint text        NOT NULL,
    nonce       bytea       NOT NULL,
    expires_at  timestamptz NOT NULL,
    PRIMARY KEY (tenant, id)
);
