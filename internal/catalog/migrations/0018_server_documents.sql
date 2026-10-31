-- Server-mode documents (D-12, S4a): the storage role splits the text,
-- builds the manifest and binds each unit in the catalog; there is no
-- client signature or unit descriptor. A client-mode version keeps both.
ALTER TABLE document_versions ALTER COLUMN manifest_signature DROP NOT NULL;
ALTER TABLE document_versions ALTER COLUMN signer DROP NOT NULL;
ALTER TABLE document_versions ADD CONSTRAINT document_versions_signature_check
    CHECK ((encryption = 'client') = (signer IS NOT NULL AND manifest_signature IS NOT NULL));
ALTER TABLE document_units ALTER COLUMN descriptor DROP NOT NULL;
ALTER TABLE document_units ALTER COLUMN descriptor_signature DROP NOT NULL;
ALTER TABLE document_units ADD CONSTRAINT document_units_descriptor_check CHECK ((descriptor IS NULL) = (descriptor_signature IS NULL));
