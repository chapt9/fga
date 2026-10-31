-- Server-mode recovery (specification 2.6.1, SSE-006, D-12 stretch S6).
-- Final removal of a server-mode version destroys its sealed data key and
-- records when; a version keeps its sealed key otherwise.
ALTER TABLE object_versions ADD COLUMN key_destroyed_at timestamptz;
ALTER TABLE object_versions DROP CONSTRAINT object_versions_sealed_key_check;
ALTER TABLE object_versions ADD CONSTRAINT object_versions_sealed_key_check
    CHECK ((sealed_key IS NULL) = (kek_version IS NULL)
           AND (encryption = 'server') = (sealed_key IS NOT NULL OR key_destroyed_at IS NOT NULL)
           AND NOT (sealed_key IS NOT NULL AND key_destroyed_at IS NOT NULL)
           AND (key_destroyed_at IS NULL OR state = 'RETIRED'));
