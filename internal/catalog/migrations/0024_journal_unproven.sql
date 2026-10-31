-- A restore whose catalog kept no record of how far the security journal
-- reached (for example onto an empty catalog) cannot show the journal
-- complete after the backup; reconcile then needs an operator statement
-- (specification 2.6.2, AVL-008, review v3 F02).
ALTER TABLE authority_state ADD COLUMN journal_unproven boolean NOT NULL DEFAULT false;
