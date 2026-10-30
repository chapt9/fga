-- Authoritative state for the decision core (specification 2.2, Part 1).
-- Every table is keyed by tenant, and cross-table references include the
-- tenant, so a row can only point at rows of its own tenant (DAT-001).

CREATE TABLE identities (
    tenant     text    NOT NULL,
    id         text    NOT NULL,
    revision   bigint  NOT NULL,
    disabled   boolean NOT NULL DEFAULT false,
    roles      text[]  NOT NULL DEFAULT '{}',
    attributes jsonb   NOT NULL DEFAULT '{}',
    PRIMARY KEY (tenant, id)
);

CREATE TABLE delegations (
    tenant     text        NOT NULL,
    id         text        NOT NULL,
    actor      text        NOT NULL,
    subject    text        NOT NULL,
    audience   text        NOT NULL,
    grants     jsonb       NOT NULL,
    expires_at timestamptz NOT NULL,
    parent     text,
    revision   bigint      NOT NULL,
    revoked    boolean     NOT NULL DEFAULT false,
    PRIMARY KEY (tenant, id),
    FOREIGN KEY (tenant, parent)  REFERENCES delegations (tenant, id),
    FOREIGN KEY (tenant, actor)   REFERENCES identities (tenant, id),
    FOREIGN KEY (tenant, subject) REFERENCES identities (tenant, id)
);

CREATE TABLE resources (
    tenant            text   NOT NULL,
    id                text   NOT NULL,
    type              text   NOT NULL,
    scope             text   NOT NULL DEFAULT '',
    version           bigint NOT NULL,
    generation        bigint NOT NULL,
    metadata_revision bigint NOT NULL,
    attributes        jsonb  NOT NULL DEFAULT '{}',
    PRIMARY KEY (tenant, id)
);

CREATE TABLE aliases (
    tenant      text NOT NULL,
    namespace   text NOT NULL,
    name        text NOT NULL,
    resource_id text NOT NULL,
    PRIMARY KEY (tenant, namespace, name),
    FOREIGN KEY (tenant, resource_id) REFERENCES resources (tenant, id)
);

CREATE TABLE capabilities (
    tenant        text NOT NULL,
    actor         text NOT NULL,
    resource_type text NOT NULL,
    action        text NOT NULL,
    PRIMARY KEY (tenant, actor, resource_type, action),
    FOREIGN KEY (tenant, actor) REFERENCES identities (tenant, id)
);

CREATE TABLE tenant_epochs (
    tenant         text   PRIMARY KEY,
    required_epoch bigint NOT NULL
);

CREATE TABLE consumed_decisions (
    decision_id text        PRIMARY KEY,
    valid_until timestamptz NOT NULL,
    consumed_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE audit_outbox (
    id           text   PRIMARY KEY,
    seq          bigint GENERATED ALWAYS AS IDENTITY,
    tenant       text   NOT NULL,
    kind         text   NOT NULL,
    event        jsonb  NOT NULL,
    delivered_at timestamptz
);

CREATE INDEX audit_outbox_pending ON audit_outbox (seq) WHERE delivered_at IS NULL;
