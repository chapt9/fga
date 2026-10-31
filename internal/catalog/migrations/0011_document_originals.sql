-- The encrypted original file of a document version (CNT-003, DOC-006):
-- an objects row of kind 'original' with one version under its own key.
-- It has no key and no resource of its own; it is reached only through its
-- document version, with raw-read on the version and read on every unit.
ALTER TABLE objects DROP CONSTRAINT objects_kind_check;
ALTER TABLE objects ADD CONSTRAINT objects_kind_check CHECK (kind IN ('object', 'document', 'unit', 'original'));
ALTER TABLE objects DROP CONSTRAINT objects_check;
ALTER TABLE objects ADD CONSTRAINT objects_key_check CHECK ((kind IN ('unit', 'original')) = (key = ''));
ALTER TABLE upload_intents DROP CONSTRAINT upload_intents_kind_check;
ALTER TABLE upload_intents ADD CONSTRAINT upload_intents_kind_check CHECK (kind IN ('object', 'unit', 'original'));
ALTER TABLE upload_intents DROP CONSTRAINT upload_intents_check;
ALTER TABLE upload_intents ADD CONSTRAINT upload_intents_document_check CHECK ((kind IN ('unit', 'original')) = (document_intent IS NOT NULL));

ALTER TABLE document_intents ADD COLUMN original jsonb;
ALTER TABLE document_versions ADD COLUMN original uuid;
ALTER TABLE document_versions ADD COLUMN original_version uuid;
ALTER TABLE document_versions ADD FOREIGN KEY (tenant, original_version) REFERENCES object_versions (tenant, id);
ALTER TABLE document_versions ADD CONSTRAINT document_versions_original_check CHECK ((original IS NULL) = (original_version IS NULL));
