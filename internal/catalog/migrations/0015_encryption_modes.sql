-- Encryption modes (specification 2.6, D-12, ENC-001 to ENC-003). Every
-- bucket is in server mode or client mode. A bucket's mode is copied to
-- each upload it admits, and each version keeps the mode it was published
-- under. Data that predates modes was client-encrypted, so existing
-- buckets, intents and versions become client mode (ENC-003). The columns
-- have no default: every insert names its mode.
ALTER TABLE buckets ADD COLUMN encryption text NOT NULL DEFAULT 'client' CHECK (encryption IN ('server', 'client'));
ALTER TABLE buckets ALTER COLUMN encryption DROP DEFAULT;
ALTER TABLE upload_intents ADD COLUMN encryption text NOT NULL DEFAULT 'client' CHECK (encryption IN ('server', 'client'));
ALTER TABLE upload_intents ALTER COLUMN encryption DROP DEFAULT;
ALTER TABLE document_intents ADD COLUMN encryption text NOT NULL DEFAULT 'client' CHECK (encryption IN ('server', 'client'));
ALTER TABLE document_intents ALTER COLUMN encryption DROP DEFAULT;
ALTER TABLE document_versions ADD COLUMN encryption text NOT NULL DEFAULT 'client' CHECK (encryption IN ('server', 'client'));
ALTER TABLE document_versions ALTER COLUMN encryption DROP DEFAULT;
-- A delete marker has no payload and no mode.
ALTER TABLE object_versions ADD COLUMN encryption text CHECK (encryption IN ('server', 'client'));
UPDATE object_versions SET encryption = 'client' WHERE NOT delete_marker;
ALTER TABLE object_versions ADD CONSTRAINT object_versions_encryption_check2 CHECK (delete_marker = (encryption IS NULL));

-- The mode is visible to policy as the attribute "encryption" of the
-- bucket and of every resource stored in it: its objects, documents,
-- units, entries, originals and derived outputs, and its document
-- versions. Envelopes keep the attributes of the version they were made
-- for. Open intents carry it in their planned attributes.
UPDATE resources SET attributes = attributes || '{"encryption": "client"}'
 WHERE type = 'storage.bucket'
    OR (tenant, id) IN (SELECT tenant, id::text FROM objects)
    OR (tenant, id) IN (SELECT tenant, id::text FROM document_versions);
UPDATE upload_intents SET planned_attributes = planned_attributes || '{"encryption": "client"}';
UPDATE document_intents SET planned_attributes = planned_attributes || '{"encryption": "client"}';
