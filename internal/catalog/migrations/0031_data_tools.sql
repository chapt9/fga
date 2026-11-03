-- Data tools (docs/design/mcp-data-tools.md, DTL-001): reviewed views of
-- one source's readings. Their versions hold the record fga.data-tool/v1
-- as stored and digested; at most one is the draft and at most one is
-- active. A review registers the tool's agent.tool resource
-- "mcp.tool:<name>". Data tools grant nothing, so their changes are
-- audited and not journaled.
CREATE TABLE data_tools (
    tenant         text        NOT NULL REFERENCES tenants (name),
    id             text        NOT NULL,
    source         text        NOT NULL,
    disabled       boolean     NOT NULL DEFAULT false,
    active_version integer,
    created_at     timestamptz NOT NULL,
    PRIMARY KEY (tenant, id),
    FOREIGN KEY (tenant, source) REFERENCES sources (tenant, id)
);

CREATE TABLE data_tool_versions (
    tenant      text        NOT NULL,
    tool        text        NOT NULL,
    version     integer     NOT NULL CHECK (version > 0),
    definition  text        NOT NULL,
    digest      text        NOT NULL,
    state       text        NOT NULL CHECK (state IN ('DRAFT', 'ACTIVE', 'SUPERSEDED')),
    author      text        NOT NULL,
    reviewer    text,
    created_at  timestamptz NOT NULL,
    reviewed_at timestamptz,
    PRIMARY KEY (tenant, tool, version),
    FOREIGN KEY (tenant, tool) REFERENCES data_tools (tenant, id)
);

CREATE UNIQUE INDEX data_tool_versions_one_draft ON data_tool_versions (tenant, tool) WHERE state = 'DRAFT';
CREATE UNIQUE INDEX data_tool_versions_one_active ON data_tool_versions (tenant, tool) WHERE state = 'ACTIVE';
