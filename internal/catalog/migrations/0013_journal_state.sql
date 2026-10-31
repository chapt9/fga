-- The security journal the catalog is bound to, and how many entries it
-- had when the catalog last recorded a journaled change (review finding 1,
-- AVL-008, KEY-017). Restore and reconcile refuse a journal with another
-- identity or fewer entries: a lost or older journal would silently drop
-- revocations.
CREATE TABLE journal_state (
    id         smallint PRIMARY KEY CHECK (id = 1),
    journal_id text     NOT NULL,
    entries    bigint   NOT NULL CHECK (entries >= 0)
);
