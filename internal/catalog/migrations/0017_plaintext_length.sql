-- The plaintext length of a server-mode upload and version, which the
-- storage role measures while it encrypts and tells a reader (SSE-005).
-- A client-mode version has none: the server never sees its plaintext.
ALTER TABLE upload_intents ADD COLUMN plaintext_length bigint CHECK (plaintext_length >= 0);
ALTER TABLE upload_intents ADD CONSTRAINT upload_intents_plaintext_length_check2 CHECK (encryption = 'server' OR plaintext_length IS NULL);
ALTER TABLE object_versions ADD COLUMN plaintext_length bigint CHECK (plaintext_length >= 0);
ALTER TABLE object_versions ADD CONSTRAINT object_versions_plaintext_length_check2 CHECK ((encryption = 'server') = (plaintext_length IS NOT NULL));
