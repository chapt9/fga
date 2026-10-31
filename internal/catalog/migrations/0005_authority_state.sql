-- The deployment's recovery incarnation and admission state (specification
-- 2.5, AVL-008, DEC-011). One row. Restore closes admission and advances
-- the incarnation; decisions bind the incarnation they were made in, and
-- the authority fence rejects any other.
CREATE TABLE authority_state (
    id             smallint    PRIMARY KEY CHECK (id = 1),
    incarnation    bigint      NOT NULL CHECK (incarnation > 0),
    admission_open boolean     NOT NULL,
    changed_at     timestamptz NOT NULL DEFAULT now()
);
INSERT INTO authority_state (id, incarnation, admission_open) VALUES (1, 1, true);

ALTER TABLE consumed_decisions ADD COLUMN incarnation bigint NOT NULL DEFAULT 1;
