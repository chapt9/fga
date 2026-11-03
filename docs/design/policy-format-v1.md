# Policy format v1 (proposed)

Status: proposal, 30 October 2026. Not yet approved; the engine is not coded until it is.

The format is the project's own (D-01). Its ideas come from attribute-based policy engines in general, including Cerbos: resource policies, roles, conditions and scopes. It does not copy any upstream format, and it deliberately drops the precedence rules that caused trouble in review (findings F-01 and V-005).

## Document

```json
{
  "format": "fga.policy/v1",
  "set": "business",
  "resource": "document.text_unit",
  "scope": "acme",
  "rules": [
    {
      "id": "reviewers-read-own-projects",
      "effect": "allow",
      "actions": ["read"],
      "roles": ["reviewer"],
      "when": "resource.project_id in principal.project_ids"
    }
  ]
}
```

| Field | Meaning |
|---|---|
| `format` | Always `fga.policy/v1`. |
| `set` | `business` (tenant-authored) or `ceiling` (platform, deny rules only). |
| `resource` | A resource type from the registry, for example `document.text_unit`. |
| `scope` | Dot-separated scope (`acme.eu`); empty means root. A selector, not proof of tenant. |
| `rules[].id` | Unique within the bundle. Used in diagnostics and audit. |
| `rules[].effect` | `allow` or `deny`. |
| `rules[].actions` | Registered actions, or `*`. |
| `rules[].roles` | Roles, or `*` for any role. |
| `rules[].when` | Optional condition. Absent means always. |
| `rules[].requires` | Optional prerequisites of a business allow rule: `approval`, `reservation` (added for R1-B). |

## Evaluation

For one principal, resource and action:

1. **Candidates:** rules of the requested set for the resource type, taken from the request's scope and each ancestor up to root. For example, for `acme.eu` the scopes are `acme.eu`, `acme`, then root.
2. **Match:** a rule matches if it lists the action (or `*`), the principal holds one of its roles (or `*`), and its condition is true or absent.
3. **Business set:** any matching deny gives DENY; otherwise any matching allow gives ALLOW; otherwise DENY. Deny always overrides allow, across roles and across scopes.
4. **Ceiling set:** any matching deny is an objection (DENY); otherwise no objection. No ceiling rule for a type means no objection.
5. **Prerequisites:** an allow carries the union of the `requires` lists of every matching allow rule. The decision is then NEEDS_APPROVAL or NEEDS_RESERVATION until the prerequisite is satisfied through the control plane (APR-001, APR-007).
6. **Errors:** if any candidate rule's condition fails to evaluate, the action is DENY (business) or an objection (ceiling). There is no lenient mode.

The consequences of this design:
- A tenant scope can add allows but cannot lift a parent's deny.
- Holding an extra role can never undo a deny, so the role-path trap of V-005 cannot occur.
- A ceiling cannot be bypassed, because nothing takes precedence over a deny.

## Conditions

The proposal is CEL, through the cel-go library (Google, Apache-2.0), with these variables:

| Variable | Contents |
|---|---|
| `principal` | `id`, `roles`, `attributes` |
| `resource` | `type`, `id`, `scope`, `attributes` |
| `request` | `now` |

Expressions are pure, compiled once per bundle and run under a cost limit (POL-009). The alternative is a small expression language of our own (comparison, `in`, `and`, `or`, `not`): no dependency, but less expressive and more code to own.

**Time conditions (POL-008, evaluator `fga.evaluator/2`).** `request.now` may appear only as one side of a direct comparison. The other side is an anchor: a timestamp literal, `timestamp("2027-01-15T09:00:00Z")`, or a resource attribute's time, `timestamp(resource.attributes.published_at)`, either optionally plus or minus a duration literal. Every other use is rejected at bundle load, including arithmetic on `request.now` itself, a principal's attribute, or a duration that is not a literal. A decision is valid at most until the earliest anchor instant not before the request time, among all rules that list the action, whether or not they matched (DEC-005). For an attribute, that instant is read from the resource the decision is bound to, so a change of the attribute makes the decision stale anyway. An absent attribute bounds nothing, since no comparison with it can be evaluated. A value that is not an RFC 3339 string ends the decision at once. Example, the last day of a document's versions:

```
has(resource.attributes.published_at) && request.now < timestamp(resource.attributes.published_at) + duration("24h")
```

## Validation at bundle load

A bundle is rejected if any of these hold:
- unknown fields, duplicate rule IDs, or an unknown resource type or action;
- an allow rule in the ceiling set;
- a condition that does not compile with the declared variable types;
- rule, scope or expression-size limits are exceeded.

## Left out of v1

These can be added later without changing the meaning of existing policies:
- principal-specific policies;
- derived roles;
- shared variables and constants;
- policy outputs (needed later for obligations);
- YAML authoring, which would compile to the same JSON.

## Specification impact

Specification 2.2 replaces:
- POL-002 (format and semantics) and POL-012 (oracle);
- POL-014 (scope modes) and TEST-004;
- the examples in Section 1.4.2;
- vectors V-001, V-004, V-005, V-008 and V-012. Under deny-overrides V-005 becomes DENY.
