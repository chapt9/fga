-- The highest policy epoch fga-decision activated (REL-003; security
-- review of 4 November 2026, finding 6): a start with a lower epoch is
-- refused, so a rollback is a new release with a higher epoch, at a
-- restart as while running.
ALTER TABLE authority_state ADD COLUMN activated_epoch bigint NOT NULL DEFAULT 0;
