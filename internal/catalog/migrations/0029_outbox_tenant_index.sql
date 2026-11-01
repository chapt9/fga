-- Each tenant's undelivered audit events are counted on every append when
-- a role bounds them (outbox_tenant_capacity, AUD-002).
CREATE INDEX audit_outbox_pending_tenant ON audit_outbox (tenant) WHERE delivered_at IS NULL;
