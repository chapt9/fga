-- Content-signing keys become resources, so looking one up is a policy
-- decision like every other action (default deny, ruling 7).
INSERT INTO resources (tenant, id, type, scope, version, generation, metadata_revision, attributes)
SELECT tenant, fingerprint, 'crypto.signing-key', '', 1, revision, 1,
       jsonb_build_object('principal', principal, 'status', status)
  FROM signing_keys
ON CONFLICT DO NOTHING;
