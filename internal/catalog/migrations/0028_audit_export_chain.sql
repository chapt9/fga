-- The head of the audit export chain (AUD-002, AUD-003): the digest of the
-- last signed link the exporter wrote, updated with the delivery marks of
-- that link's events, so a truncated or replaced export directory is
-- evident (docs/design/audit-export.md).
CREATE TABLE audit_export_state (
    id         int         PRIMARY KEY CHECK (id = 1),
    head       text        NOT NULL,
    file       text        NOT NULL,
    updated_at timestamptz NOT NULL
);
