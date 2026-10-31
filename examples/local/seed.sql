-- Example tenant for the decision-only walkthrough. Load after fga-decision
-- has migrated the schema. The storage walkthrough uses fga-admin instead.
INSERT INTO identities (tenant, id, revision, disabled, roles, attributes) VALUES
  ('t-acme', 'user-42', 88, false, '{member}', '{"projects": ["p1"]}'),
  ('t-acme', 'agent-7', 12, false, '{agent}', '{}');
INSERT INTO delegations VALUES
  ('t-acme', 'dlg-5', 'agent-7', 'user-42', 'local-dev',
   '[{"resource_type": "storage.object", "actions": ["read"]}]', now() + interval '1 day', NULL, 3, false);
INSERT INTO resources VALUES
  ('t-acme', 'obj-1', 'storage.object', '', 1, 3, 1, '{"project": "p1", "owner": "user-9"}'),
  ('t-acme', 'obj-2', 'storage.object', '', 1, 2, 1, '{"project": "p2", "owner": "user-9"}');
INSERT INTO aliases VALUES
  ('t-acme', 'native.object', 'reports/q3.txt', 'obj-1'),
  ('t-acme', 'native.object', 'reports/q4.txt', 'obj-2');
INSERT INTO capabilities VALUES ('t-acme', 'agent-7', 'storage.object', 'read');
INSERT INTO tenant_epochs VALUES ('t-acme', 1);
