-- Example tenant for a local run. Load after fga-decision has migrated the schema.
INSERT INTO identities VALUES
  ('t-acme', 'user-42', 88, false, '{reviewer}', '{"project_ids": ["p1"]}'),
  ('t-acme', 'agent-7', 12, false, '{agent}', '{}');
INSERT INTO delegations VALUES
  ('t-acme', 'dlg-5', 'agent-7', 'user-42', 'local-dev',
   '[{"resource_type": "document.text_unit", "actions": ["read"]}]', now() + interval '1 day', NULL, 3, false);
INSERT INTO resources VALUES
  ('t-acme', 'u-1', 'document.text_unit', '', 7, 17, 2, '{"project_id": "p1", "state": "LIVE"}'),
  ('t-acme', 'u-2', 'document.text_unit', '', 1, 4, 1, '{"project_id": "p1", "state": "DRAFT"}');
INSERT INTO aliases VALUES
  ('t-acme', 'mcp', 'doc://q3#overview', 'u-1'),
  ('t-acme', 'mcp', 'doc://q3#draft', 'u-2');
INSERT INTO capabilities VALUES ('t-acme', 'agent-7', 'document.text_unit', 'read');
INSERT INTO tenant_epochs VALUES ('t-acme', 1);
