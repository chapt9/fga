-- Every resource of a bucket carries the bucket's encryption mode (ENC-001).
-- Document versions and derived outputs published before review v3 F08
-- were created without it; they take it now, and their metadata revision
-- advances, as on a mode change.
UPDATE resources r SET attributes = r.attributes || jsonb_build_object('encryption', b.encryption),
                       metadata_revision = r.metadata_revision + 1
  FROM objects o JOIN buckets b ON b.tenant = o.tenant AND b.id = o.bucket
 WHERE r.tenant = o.tenant AND r.id = o.id::text AND r.type = 'document.derived' AND NOT r.attributes ? 'encryption';

UPDATE resources r SET attributes = r.attributes || jsonb_build_object('encryption', b.encryption),
                       metadata_revision = r.metadata_revision + 1
  FROM document_versions d JOIN objects o ON o.tenant = d.tenant AND o.id = d.document
       JOIN buckets b ON b.tenant = o.tenant AND b.id = o.bucket
 WHERE r.tenant = d.tenant AND r.id = d.id::text AND r.type = 'document.version' AND NOT r.attributes ? 'encryption';
