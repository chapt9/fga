-- Sign-in keys (docs/design/sign-in-keys.md): the Ed25519 public keys an
-- account signs its own short access tokens with. A key signs only for its
-- owner, and a REMOVED key never signs again; a removal is journaled
-- first, so a restore takes it away again. Limits narrow what a token the
-- key signed may do (services, highest label, spaces); they are fixed when
-- the key is registered.
CREATE TABLE sign_in_keys (
    tenant      text        NOT NULL,
    fingerprint text        NOT NULL,
    principal   text        NOT NULL,
    public_key  bytea       NOT NULL,
    label       text        NOT NULL,
    limits      jsonb       NOT NULL,
    status      text        NOT NULL CHECK (status IN ('ACTIVE', 'REMOVED')),
    revision    bigint      NOT NULL,
    created_at  timestamptz NOT NULL,
    changed_at  timestamptz NOT NULL,
    PRIMARY KEY (tenant, fingerprint),
    FOREIGN KEY (tenant, principal) REFERENCES identities (tenant, id)
);

CREATE INDEX sign_in_keys_principal ON sign_in_keys (tenant, principal);
