-- Server-mode derived outputs (D-12, S4b): the lineage is the storage
-- role's record of the sources the uploader declared in its authenticated
-- request, bound to the caller's decision; it has no client signature.
ALTER TABLE derived_versions ALTER COLUMN lineage_signature DROP NOT NULL;
