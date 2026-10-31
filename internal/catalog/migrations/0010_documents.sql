-- Documents and text units (R1-C, docs/design/documents.md, DOC-001 to
-- DOC-005). A document is an objects row of kind 'document' with its own
-- head of document versions; a unit is an objects row of kind 'unit' with
-- one immutable version holding its own ciphertext. Units have no key: they
-- are reached only through a document version, never through the object
-- API or listings.
ALTER TABLE objects ADD COLUMN kind text NOT NULL DEFAULT 'object' CHECK (kind IN ('object', 'document', 'unit'));
ALTER TABLE objects DROP CONSTRAINT objects_tenant_bucket_key_key;
CREATE UNIQUE INDEX objects_key ON objects (tenant, bucket, key) WHERE kind IN ('object', 'document');
ALTER TABLE objects ADD CHECK ((kind = 'unit') = (key = ''));

CREATE TABLE document_versions (
    tenant                text        NOT NULL,
    id                    uuid        NOT NULL,
    document              uuid        NOT NULL,
    manifest              bytea       NOT NULL,
    manifest_signature    text        NOT NULL,
    manifest_digest       text        NOT NULL,
    signer                text        NOT NULL,
    extraction_version    text        NOT NULL,
    normalization_version text        NOT NULL,
    state                 text        NOT NULL CHECK (state IN ('LIVE', 'WITHDRAWN')),
    created_at            timestamptz NOT NULL,
    PRIMARY KEY (tenant, id),
    FOREIGN KEY (tenant, document) REFERENCES objects (tenant, id)
);
-- Like the object head (0007), the document head is deferrable so that
-- restore can load heads and versions in one transaction.
ALTER TABLE objects ADD COLUMN current_document_version uuid;
ALTER TABLE objects ADD CONSTRAINT objects_current_document_version_fkey FOREIGN KEY (tenant, current_document_version)
    REFERENCES document_versions (tenant, id) DEFERRABLE INITIALLY IMMEDIATE;

-- Membership: the exact unit versions of a document version, in order,
-- each with its document-specific signed descriptor (DOC-001). A unit
-- version referenced by a LIVE document version cannot be withdrawn or
-- reclaimed (DOC-002, V-064).
CREATE TABLE document_units (
    tenant               text    NOT NULL,
    document_version     uuid    NOT NULL,
    position             integer NOT NULL CHECK (position >= 0),
    unit                 uuid    NOT NULL,
    unit_version         uuid    NOT NULL,
    descriptor           bytea   NOT NULL,
    descriptor_signature text    NOT NULL,
    PRIMARY KEY (tenant, document_version, position),
    UNIQUE (tenant, document_version, unit),
    FOREIGN KEY (tenant, document_version) REFERENCES document_versions (tenant, id),
    FOREIGN KEY (tenant, unit_version) REFERENCES object_versions (tenant, id)
);
CREATE INDEX document_units_by_version ON document_units (tenant, unit_version);

-- A unit envelope belongs to one document version (profile 2, V-152):
-- reusing a unit in another document version gives it other envelopes.
ALTER TABLE envelopes ADD COLUMN document_version uuid;
ALTER TABLE envelopes ADD FOREIGN KEY (tenant, document_version) REFERENCES document_versions (tenant, id);
ALTER TABLE envelopes DROP CONSTRAINT envelopes_tenant_version_recipient_generation_key;
DROP INDEX envelopes_one_active;
CREATE UNIQUE INDEX envelopes_generation ON envelopes
    (tenant, version, recipient, generation, coalesce(document_version, '00000000-0000-0000-0000-000000000000'));
CREATE UNIQUE INDEX envelopes_one_active ON envelopes
    (tenant, version, recipient, coalesce(document_version, '00000000-0000-0000-0000-000000000000')) WHERE status = 'ACTIVE';

-- Document upload intents: one per document version being published, with
-- one unit intent (an upload_intents row of kind 'unit') per new unit.
CREATE TABLE document_intents (
    tenant              text        NOT NULL,
    id                  uuid        NOT NULL,
    principal           text        NOT NULL,
    idempotency_key     text        NOT NULL,
    request_digest      text        NOT NULL,
    bucket              uuid        NOT NULL,
    key                 text        NOT NULL,
    document            uuid        NOT NULL,
    new_document        boolean     NOT NULL,
    document_version    uuid        NOT NULL,
    expected_generation bigint      NOT NULL,
    planned_scope       text        NOT NULL,
    planned_attributes  jsonb       NOT NULL,
    -- The unit plan: per position, a new unit's intent and identifiers or
    -- the reused unit version.
    units               jsonb       NOT NULL,
    state               text        NOT NULL CHECK (state IN ('RESERVED', 'COMMITTED', 'ABORTED')),
    result              jsonb,
    expires_at          timestamptz NOT NULL,
    created_at          timestamptz NOT NULL,
    PRIMARY KEY (tenant, id),
    UNIQUE (tenant, principal, idempotency_key),
    FOREIGN KEY (tenant, bucket) REFERENCES buckets (tenant, id)
);
ALTER TABLE upload_intents ADD COLUMN kind text NOT NULL DEFAULT 'object' CHECK (kind IN ('object', 'unit'));
ALTER TABLE upload_intents ADD COLUMN document_intent uuid;
ALTER TABLE upload_intents ADD FOREIGN KEY (tenant, document_intent) REFERENCES document_intents (tenant, id);
ALTER TABLE upload_intents ADD CHECK ((kind = 'unit') = (document_intent IS NOT NULL));
