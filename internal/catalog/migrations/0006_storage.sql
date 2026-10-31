-- R1-B object storage, envelopes and key registries (specification 2.5,
-- Part 3, Part 4; docs/design/storage-r1b.md). Every key includes the
-- tenant and every reference includes it, so a row can only point at rows
-- of its own tenant (DAT-001). Buckets, objects, envelopes and recipient
-- keys also have rows in resources, which carry their policy attributes,
-- generation and metadata revision for the decision role and the fence.

-- Tenants get a UUID for payload bindings (CRY-003).
CREATE TABLE tenants (
    name text PRIMARY KEY,
    id   uuid NOT NULL UNIQUE
);

CREATE TABLE buckets (
    tenant          text NOT NULL REFERENCES tenants (name),
    id              uuid NOT NULL,
    name            text NOT NULL,
    scope           text NOT NULL DEFAULT '',
    default_project text NOT NULL DEFAULT '',
    default_label   text NOT NULL DEFAULT '',
    PRIMARY KEY (tenant, id),
    UNIQUE (tenant, name)
);

-- The object head. An object exists for users once it has a current
-- version; a delete marker can be current.
CREATE TABLE objects (
    tenant          text NOT NULL,
    id              uuid NOT NULL,
    bucket          uuid NOT NULL,
    key             text NOT NULL,
    current_version uuid,
    PRIMARY KEY (tenant, id),
    UNIQUE (tenant, bucket, key),
    FOREIGN KEY (tenant, bucket) REFERENCES buckets (tenant, id)
);

CREATE TABLE object_versions (
    tenant               text        NOT NULL,
    id                   uuid        NOT NULL,
    object               uuid        NOT NULL,
    delete_marker        boolean     NOT NULL DEFAULT false,
    crypto_version       uuid,
    blob                 uuid,
    state                text        NOT NULL CHECK (state IN ('STAGED', 'LIVE', 'ABORTED', 'QUARANTINED', 'WITHDRAWN', 'RETIRED')),
    ciphertext_length    bigint,
    ciphertext_sha256    text,
    suite                integer,
    format               integer,
    signer               text,
    descriptor           bytea,
    descriptor_signature text,
    created_at           timestamptz NOT NULL,
    published_at         timestamptz,
    PRIMARY KEY (tenant, id),
    UNIQUE (tenant, blob),
    FOREIGN KEY (tenant, object) REFERENCES objects (tenant, id),
    -- A payload version has all of its binding; a delete marker has none.
    CHECK (delete_marker = (blob IS NULL)),
    CHECK (delete_marker OR (crypto_version IS NOT NULL AND ciphertext_length > 0 AND ciphertext_sha256 IS NOT NULL
                             AND suite IS NOT NULL AND format IS NOT NULL AND signer IS NOT NULL AND descriptor IS NOT NULL))
);

ALTER TABLE objects ADD FOREIGN KEY (tenant, current_version) REFERENCES object_versions (tenant, id);

-- Upload intents (PUB-002, KEY-003). An intent owns the identities of one
-- encrypted attempt; retries reuse them, a new attempt needs a new intent.
CREATE TABLE upload_intents (
    tenant              text        NOT NULL,
    id                  uuid        NOT NULL,
    principal           text        NOT NULL,
    actor               text        NOT NULL,
    delegation          text        NOT NULL DEFAULT '',
    idempotency_key     text        NOT NULL,
    request_digest      text        NOT NULL,
    bucket              uuid        NOT NULL,
    key                 text        NOT NULL,
    object              uuid        NOT NULL,
    new_object          boolean     NOT NULL,
    version             uuid        NOT NULL,
    crypto_version      uuid        NOT NULL,
    blob                uuid        NOT NULL,
    attempt             uuid        NOT NULL,
    expected_generation bigint      NOT NULL,
    if_match            text        NOT NULL DEFAULT '',
    if_none_match       boolean     NOT NULL DEFAULT false,
    planned_scope       text        NOT NULL,
    planned_attributes  jsonb       NOT NULL,
    state               text        NOT NULL CHECK (state IN ('RESERVED', 'STAGED', 'COMMITTED', 'ABORTED')),
    ciphertext_length   bigint,
    ciphertext_sha256   text,
    result              jsonb,
    expires_at          timestamptz NOT NULL,
    created_at          timestamptz NOT NULL,
    PRIMARY KEY (tenant, id),
    UNIQUE (tenant, principal, idempotency_key),
    UNIQUE (tenant, blob),
    FOREIGN KEY (tenant, bucket) REFERENCES buckets (tenant, id)
);

-- Content-signing keys (RCP-008, RCP-011). Retired keys keep verifying
-- historical content; compromised keys fail closed.
CREATE TABLE signing_keys (
    tenant      text        NOT NULL,
    fingerprint text        NOT NULL,
    principal   text        NOT NULL,
    public_key  bytea       NOT NULL,
    status      text        NOT NULL CHECK (status IN ('ACTIVE', 'RETIRED', 'COMPROMISED')),
    revision    bigint      NOT NULL,
    created_at  timestamptz NOT NULL,
    changed_at  timestamptz NOT NULL,
    PRIMARY KEY (tenant, fingerprint),
    FOREIGN KEY (tenant, principal) REFERENCES identities (tenant, id)
);

-- Opaque recipient envelopes (KEY-001, RCP-005). The server cannot open
-- them. At most one active envelope per version and recipient.
CREATE TABLE envelopes (
    tenant      text        NOT NULL,
    id          uuid        NOT NULL,
    object      uuid        NOT NULL,
    version     uuid        NOT NULL,
    recipient   text        NOT NULL,
    key_version bigint      NOT NULL,
    generation  bigint      NOT NULL,
    context     bytea       NOT NULL,
    ciphertext  bytea       NOT NULL,
    signature   text        NOT NULL,
    signer      text        NOT NULL,
    digest      text        NOT NULL,
    status      text        NOT NULL CHECK (status IN ('ACTIVE', 'RETIRED')),
    created_at  timestamptz NOT NULL,
    PRIMARY KEY (tenant, id),
    UNIQUE (tenant, version, recipient, generation),
    FOREIGN KEY (tenant, version)   REFERENCES object_versions (tenant, id),
    FOREIGN KEY (tenant, recipient) REFERENCES recipient_keys (tenant, fingerprint)
);
CREATE UNIQUE INDEX envelopes_one_active ON envelopes (tenant, version, recipient) WHERE status = 'ACTIVE';

-- One-use enrollment challenges (RCP-002). The ephemeral X25519 private key
-- of a recipient challenge lives only until the challenge is used or
-- expires.
CREATE TABLE enrollment_challenges (
    tenant            text        NOT NULL,
    id                uuid        NOT NULL,
    principal         text        NOT NULL,
    fingerprint       text        NOT NULL,
    nonce             bytea       NOT NULL,
    ephemeral_private bytea       NOT NULL,
    expires_at        timestamptz NOT NULL,
    PRIMARY KEY (tenant, id)
);

-- Admitted ciphertext reads and their leases (CNT-008).
CREATE TABLE read_admissions (
    tenant      text        NOT NULL,
    decision_id text        NOT NULL,
    version     uuid        NOT NULL,
    admitted_at timestamptz NOT NULL,
    lease_until timestamptz NOT NULL,
    PRIMARY KEY (tenant, decision_id),
    FOREIGN KEY (tenant, version) REFERENCES object_versions (tenant, id)
);

-- Withdrawn versions waiting for physical removal (PUB-005, PUB-006).
CREATE TABLE retirements (
    tenant       text        NOT NULL,
    version      uuid        NOT NULL,
    blob         uuid        NOT NULL,
    requested_at timestamptz NOT NULL,
    done_at      timestamptz,
    PRIMARY KEY (tenant, version),
    FOREIGN KEY (tenant, version) REFERENCES object_versions (tenant, id)
);

CREATE INDEX objects_listing ON objects (tenant, bucket, key) WHERE current_version IS NOT NULL;
