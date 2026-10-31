-- Derived outputs and lineage (R1-C, docs/design/derived-outputs.md,
-- DRV-001 to DRV-003, DRV-007 to DRV-009). A derived output is an objects
-- row of kind 'derived' with a key in its bucket and a document.derived
-- resource; it is published like an object with signed lineage and read
-- only through the derived routes, never the object API.
ALTER TABLE objects DROP CONSTRAINT objects_kind_check;
ALTER TABLE objects ADD CONSTRAINT objects_kind_check CHECK (kind IN ('object', 'document', 'unit', 'original', 'derived'));
DROP INDEX objects_key;
CREATE UNIQUE INDEX objects_key ON objects (tenant, bucket, key) WHERE kind IN ('object', 'document', 'derived');
ALTER TABLE upload_intents DROP CONSTRAINT upload_intents_kind_check;
ALTER TABLE upload_intents ADD CONSTRAINT upload_intents_kind_check CHECK (kind IN ('object', 'unit', 'original', 'derived'));

-- The signed lineage of each derived version (DRV-001), and its direct
-- sources in declared order. Sources are existing resources of the tenant:
-- storage objects and text units at an exact version, or other derived
-- outputs.
CREATE TABLE derived_versions (
    tenant            text  NOT NULL,
    version           uuid  NOT NULL,
    derived           uuid  NOT NULL,
    lineage           bytea NOT NULL,
    lineage_signature text  NOT NULL,
    effective_label   text  NOT NULL,
    depth             integer NOT NULL CHECK (depth BETWEEN 1 AND 32),
    PRIMARY KEY (tenant, version),
    FOREIGN KEY (tenant, version) REFERENCES object_versions (tenant, id)
);
CREATE TABLE lineage (
    tenant          text    NOT NULL,
    derived_version uuid    NOT NULL,
    position        integer NOT NULL CHECK (position >= 0),
    source_type     text    NOT NULL CHECK (source_type IN ('storage.object', 'document.text_unit', 'document.derived')),
    source_id       text    NOT NULL,
    source_version  uuid    NOT NULL,
    PRIMARY KEY (tenant, derived_version, position),
    FOREIGN KEY (tenant, derived_version) REFERENCES derived_versions (tenant, version),
    FOREIGN KEY (tenant, source_version) REFERENCES object_versions (tenant, id)
);
CREATE INDEX lineage_by_source ON lineage (tenant, source_version);
