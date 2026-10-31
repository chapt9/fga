-- Labels and approvals for R1-C (docs/design/labels-and-approvals.md,
-- LAB-001 to LAB-005, APR-001 to APR-005).

-- An approval binds, besides its operation digest, the target an approver
-- decides on, the policy epoch and the resource revisions it was requested
-- under (APR-001). Its revision advances on every state change and is bound
-- into the decision that relies on it (DEC-008).
ALTER TABLE approvals
    ADD COLUMN revision     bigint      NOT NULL DEFAULT 1,
    ADD COLUMN target_type  text        NOT NULL DEFAULT '',
    ADD COLUMN target_id    text        NOT NULL DEFAULT '',
    ADD COLUMN policy_epoch bigint      NOT NULL DEFAULT 0,
    ADD COLUMN bindings     jsonb       NOT NULL DEFAULT '[]',
    ADD COLUMN created_at   timestamptz NOT NULL DEFAULT now();
CREATE INDEX approvals_pending ON approvals (tenant, state, expires_at);

-- The label order of the active policy release, published by the decision
-- role when it activates a release (D-06, FLW-004). An order never changes
-- within its generation. Enforcing roles read it to tell a raise from a
-- lowering and compare its generation with the decision's.
CREATE TABLE label_orders (
    generation bigint PRIMARY KEY CHECK (generation > 0),
    labels     text[] NOT NULL CHECK (cardinality(labels) > 0)
);
CREATE TABLE label_order_active (
    id         smallint PRIMARY KEY CHECK (id = 1),
    generation bigint   NOT NULL REFERENCES label_orders
);

-- Advisory label proposals from client classifiers (LAB-002 source 3). A
-- proposal never changes a label; a principal applies one with an ordinary
-- label or relabel operation.
CREATE TABLE label_proposals (
    tenant        text        NOT NULL,
    id            uuid        NOT NULL,
    resource_type text        NOT NULL,
    resource_id   text        NOT NULL,
    label         text        NOT NULL,
    classifier    text        NOT NULL,
    proposer      text        NOT NULL,
    authoritative boolean     NOT NULL DEFAULT false CHECK (NOT authoritative),
    created_at    timestamptz NOT NULL,
    PRIMARY KEY (tenant, id)
);

-- An explicit label requested at upload (LAB-002 source 1); empty when the
-- object takes its bucket's default. It is checked with label on the
-- planned object at publication.
ALTER TABLE upload_intents ADD COLUMN label text NOT NULL DEFAULT '';
