package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"

	"fga/internal/registry"
)

var _ registry.Planner = resourceView{}

// Planned implements registry.Planner from the catalog's own rows: an
// upload intent's planned object, an envelope planned for an object (or an
// intent's object) and a recipient key, or a recipient key planned for
// enrollment.
func (v resourceView) Planned(ctx context.Context, tenant string, alias registry.Alias) (registry.Resource, error) {
	switch alias.Namespace {
	case registry.PlannedObject:
		return v.s.plannedObject(ctx, tenant, alias.Name)
	case registry.PlannedEnvelope:
		parts := strings.Split(alias.Name, "|")
		if len(parts) != 3 || parts[2] == "" {
			return registry.Resource{}, registry.ErrUnknownAlias
		}
		var object registry.Resource
		var err error
		if intent, ok := strings.CutPrefix(parts[0], "intent:"); ok {
			object, err = v.s.plannedObject(ctx, tenant, intent)
		} else {
			object, err = v.s.GetResource(ctx, tenant, parts[0])
		}
		if err != nil {
			return registry.Resource{}, err
		}
		if object.Type != "storage.object" {
			return registry.Resource{}, registry.ErrUnknownResource
		}
		var principal string
		err = v.s.pool.QueryRow(ctx, `SELECT principal FROM recipient_keys WHERE tenant = $1 AND fingerprint = $2 AND status = 'ACTIVE'`,
			tenant, parts[1]).Scan(&principal)
		if errors.Is(err, pgx.ErrNoRows) {
			return registry.Resource{}, registry.ErrUnknownResource
		}
		if err != nil {
			return registry.Resource{}, err
		}
		attrs := map[string]any{"object": object.ID, "recipient": parts[1], "recipient_principal": principal}
		for _, k := range []string{"owner", "project", "label", "bucket"} {
			if val, ok := object.Attributes[k]; ok {
				attrs[k] = val
			}
		}
		return registry.Resource{ID: parts[2], Tenant: tenant, Type: "crypto.envelope", Scope: object.Scope, Attributes: attrs}, nil
	case registry.PlannedRecipient:
		principal, fingerprint, ok := strings.Cut(alias.Name, "|")
		if !ok || principal == "" || fingerprint == "" {
			return registry.Resource{}, registry.ErrUnknownAlias
		}
		if _, err := v.s.GetIdentity(ctx, tenant, principal); err != nil {
			return registry.Resource{}, registry.ErrUnknownResource
		}
		return registry.Resource{ID: fingerprint, Tenant: tenant, Type: "crypto.recipient",
			Attributes: map[string]any{"principal": principal, "status": "PENDING"}}, nil
	}
	return registry.Resource{}, registry.ErrUnknownAlias
}

// plannedObject is the object an open upload intent for a new key will
// publish, with the protected attributes assigned at begin (RES-009).
func (s *Store) plannedObject(ctx context.Context, tenant, intent string) (registry.Resource, error) {
	r := registry.Resource{Tenant: tenant, Type: "storage.object"}
	var attrs []byte
	err := s.pool.QueryRow(ctx, `
		SELECT object::text, planned_scope, planned_attributes FROM upload_intents
		 WHERE tenant = $1 AND id::text = $2 AND new_object AND state IN ('RESERVED', 'STAGED')`, tenant, intent).
		Scan(&r.ID, &r.Scope, &attrs)
	if errors.Is(err, pgx.ErrNoRows) {
		return registry.Resource{}, registry.ErrUnknownResource
	}
	if err != nil {
		return registry.Resource{}, err
	}
	return r, json.Unmarshal(attrs, &r.Attributes)
}
