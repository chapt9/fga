-- Registered client-side label classifiers (LAB-002 source 3, D-06): a
-- classifier is a name bound to an ACTIVE content-signing key; only a
-- proposal signed by that key is recorded, and it stays advisory.
CREATE TABLE classifiers (
    tenant     text        NOT NULL,
    id         text        NOT NULL,
    signer     text        NOT NULL,
    status     text        NOT NULL CHECK (status IN ('ACTIVE', 'REVOKED')),
    revision   bigint      NOT NULL,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (tenant, id),
    FOREIGN KEY (tenant, signer) REFERENCES signing_keys (tenant, fingerprint)
);

-- What a proposal was signed over, by which key, and the signature.
ALTER TABLE label_proposals ADD COLUMN version text;
ALTER TABLE label_proposals ADD COLUMN signer text;
ALTER TABLE label_proposals ADD COLUMN signature text;
