-- Share grants (specification 2.6.1, SHR-001 to SHR-003, D-12 stretch S5).
-- A grant names one resource and one grantee principal of its tenant, the
-- actions it may be allowed and an expiry. It is an authority fact that
-- policy sees as resource.attributes.shared_with; recording or removing it
-- advances the resource's metadata revision. A removed grant keeps its
-- row, with who removed it and when; at most one grant per resource and
-- grantee is not removed.
CREATE TABLE share_grants (
    tenant        text        NOT NULL,
    id            uuid        NOT NULL,
    resource_id   text        NOT NULL,
    resource_type text        NOT NULL,
    grantee       text        NOT NULL,
    actions       text[]      NOT NULL CHECK (cardinality(actions) >= 1),
    expires_at    timestamptz NOT NULL,
    grantor       text        NOT NULL,
    decision_id   text        NOT NULL,
    created_at    timestamptz NOT NULL,
    removed_at    timestamptz,
    removed_by    text,
    PRIMARY KEY (tenant, id),
    FOREIGN KEY (tenant, resource_id) REFERENCES resources (tenant, id),
    CHECK ((removed_at IS NULL) = (removed_by IS NULL)),
    CHECK (expires_at > created_at)
);

CREATE UNIQUE INDEX share_grants_one_per_grantee ON share_grants (tenant, resource_id, grantee) WHERE removed_at IS NULL;
