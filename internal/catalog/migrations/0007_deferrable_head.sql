-- An object head and its versions reference each other. Restore loads them
-- in one transaction with this check deferred to commit (KEY-017).
ALTER TABLE objects ALTER CONSTRAINT objects_tenant_current_version_fkey DEFERRABLE INITIALLY IMMEDIATE;
