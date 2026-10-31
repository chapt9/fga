-- Every tenant has a permanent epoch row from its first appearance, so the
-- authority fence always has a row to lock (FOR SHARE) and a first epoch
-- raise waits for transitions in flight (review finding 4, REL-003). The
-- fence refuses a tenant without one.
INSERT INTO tenant_epochs (tenant, required_epoch)
SELECT tenant, 0 FROM (
    SELECT name AS tenant FROM tenants
    UNION SELECT tenant FROM identities
    UNION SELECT tenant FROM resources
) t
ON CONFLICT (tenant) DO NOTHING;
