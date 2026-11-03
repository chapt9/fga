-- Sources of JSON readings (docs/design/mcp-data-tools.md, ING-001,
-- ING-008). A source owns one bucket, created with it, which names the
-- source in buckets.source and in its resource's attributes. Its versions
-- hold the record fga.source/v1 as stored and digested; at most one is
-- the draft and at most one is active. A review is journaled, so a restore
-- cannot bring an older active version back.
ALTER TABLE buckets ADD COLUMN source text;

CREATE TABLE sources (
    tenant         text        NOT NULL REFERENCES tenants (name),
    id             text        NOT NULL,
    bucket         uuid        NOT NULL,
    disabled       boolean     NOT NULL DEFAULT false,
    active_version integer,
    created_at     timestamptz NOT NULL,
    PRIMARY KEY (tenant, id),
    UNIQUE (tenant, bucket),
    FOREIGN KEY (tenant, bucket) REFERENCES buckets (tenant, id)
);

CREATE TABLE source_versions (
    tenant      text        NOT NULL,
    source      text        NOT NULL,
    version     integer     NOT NULL CHECK (version > 0),
    definition  text        NOT NULL,
    digest      text        NOT NULL,
    state       text        NOT NULL CHECK (state IN ('DRAFT', 'ACTIVE', 'SUPERSEDED')),
    author      text        NOT NULL,
    reviewer    text,
    created_at  timestamptz NOT NULL,
    reviewed_at timestamptz,
    PRIMARY KEY (tenant, source, version),
    FOREIGN KEY (tenant, source) REFERENCES sources (tenant, id)
);

CREATE UNIQUE INDEX source_versions_one_draft ON source_versions (tenant, source) WHERE state = 'DRAFT';
CREATE UNIQUE INDEX source_versions_one_active ON source_versions (tenant, source) WHERE state = 'ACTIVE';
