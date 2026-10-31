-- Registered tool operations (R2 executor, AGT-001): the checks of each
-- reviewed tool's invocation, "tool:<id>", recorded at registration so
-- the decision role can decide them without linking tool code. The
-- executor's own tables come from its migrations.
CREATE TABLE tool_operations (
    tenant text  NOT NULL,
    name   text  NOT NULL,
    checks jsonb NOT NULL,
    PRIMARY KEY (tenant, name)
);
