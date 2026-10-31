-- Server-mode keys (specification 2.6, D-12, SSE-001 to SSE-003). The
-- keys role holds each tenant's key-encryption keys in its ring; this
-- table says which versions exist and which one seals new data keys. A
-- version is never deleted while a sealed data key refers to it.
CREATE TABLE kek_versions (
    tenant     text        NOT NULL REFERENCES tenants (name),
    version    integer     NOT NULL CHECK (version > 0),
    state      text        NOT NULL CHECK (state IN ('ACTIVE', 'RETIRED')),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (tenant, version)
);
CREATE UNIQUE INDEX kek_versions_active ON kek_versions (tenant) WHERE state = 'ACTIVE';

-- A server-mode upload gets its sealed data key from the keys role once,
-- and its version keeps it. Client-mode rows never have one.
ALTER TABLE upload_intents ADD COLUMN sealed_key bytea;
ALTER TABLE upload_intents ADD COLUMN kek_version integer;
ALTER TABLE upload_intents ADD CONSTRAINT upload_intents_sealed_key_check
    CHECK ((sealed_key IS NULL) = (kek_version IS NULL) AND (encryption = 'server' OR sealed_key IS NULL));
ALTER TABLE upload_intents ADD FOREIGN KEY (tenant, kek_version) REFERENCES kek_versions (tenant, version);
ALTER TABLE object_versions ADD COLUMN sealed_key bytea;
ALTER TABLE object_versions ADD COLUMN kek_version integer;
ALTER TABLE object_versions ADD CONSTRAINT object_versions_sealed_key_check
    CHECK ((sealed_key IS NULL) = (kek_version IS NULL) AND (encryption = 'server') = (sealed_key IS NOT NULL));
ALTER TABLE object_versions ADD FOREIGN KEY (tenant, kek_version) REFERENCES kek_versions (tenant, version);

-- A server-mode version has no client signature or descriptor; a
-- client-mode version still needs both (ENC-002).
DO $$
DECLARE c text;
BEGIN
    SELECT conname INTO STRICT c FROM pg_constraint
     WHERE conrelid = 'object_versions'::regclass AND contype = 'c' AND pg_get_constraintdef(oid) LIKE '%descriptor IS NOT NULL%';
    EXECUTE format('ALTER TABLE object_versions DROP CONSTRAINT %I', c);
END $$;
ALTER TABLE object_versions ADD CONSTRAINT object_versions_payload_check
    CHECK (delete_marker OR (crypto_version IS NOT NULL AND ciphertext_length > 0 AND ciphertext_sha256 IS NOT NULL
                             AND suite IS NOT NULL AND format IS NOT NULL
                             AND (encryption = 'server' OR (signer IS NOT NULL AND descriptor IS NOT NULL))));
