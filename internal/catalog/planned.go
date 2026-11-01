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
// intent's object) and a recipient key, a recipient key planned for
// enrollment, or a principal's own record.
func (v resourceView) Planned(ctx context.Context, tenant string, alias registry.Alias) (registry.Resource, error) {
	switch alias.Namespace {
	case registry.PlannedObject:
		return v.s.plannedObject(ctx, tenant, alias.Name)
	case registry.PlannedDocumentVersion:
		return v.s.plannedDocumentVersion(ctx, tenant, alias.Name)
	case registry.PlannedEnvelope:
		parts := strings.Split(alias.Name, "|")
		if len(parts) != 3 || parts[2] == "" {
			return registry.Resource{}, registry.ErrUnknownAlias
		}
		var object registry.Resource
		var err error
		if intent, ok := strings.CutPrefix(parts[0], "intent:"); ok {
			object, err = v.s.plannedObject(ctx, tenant, intent)
		} else if intent, ok := strings.CutPrefix(parts[0], "docintent:"); ok {
			// An envelope of a document version's original file.
			object, err = v.s.plannedDocumentVersion(ctx, tenant, intent)
		} else {
			object, err = v.s.GetResource(ctx, tenant, parts[0])
		}
		if err != nil {
			return registry.Resource{}, err
		}
		if object.Type != "storage.object" && object.Type != "document.text_unit" && object.Type != "document.version" && object.Type != "document.derived" && object.Type != "text.entry" {
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
	case registry.PlannedSigner:
		principal, fingerprint, ok := strings.Cut(alias.Name, "|")
		if !ok || principal == "" || fingerprint == "" {
			return registry.Resource{}, registry.ErrUnknownAlias
		}
		if _, err := v.s.GetIdentity(ctx, tenant, principal); err != nil {
			return registry.Resource{}, registry.ErrUnknownResource
		}
		return registry.Resource{ID: fingerprint, Tenant: tenant, Type: "crypto.signing-key",
			Attributes: map[string]any{"principal": principal, "status": "PENDING"}}, nil
	case registry.PlannedSelf:
		if _, err := v.s.GetIdentity(ctx, tenant, alias.Name); err != nil {
			return registry.Resource{}, registry.ErrUnknownResource
		}
		return registry.Resource{ID: alias.Name, Tenant: tenant, Type: "principal.self",
			Attributes: map[string]any{"principal": alias.Name}}, nil
	}
	return registry.Resource{}, registry.ErrUnknownAlias
}

// plannedObject is the object an open upload intent for a new key will
// publish, or the unit a unit intent will publish (a document.text_unit),
// with the protected attributes assigned at begin (RES-009).
func (s *Store) plannedObject(ctx context.Context, tenant, intent string) (registry.Resource, error) {
	r := registry.Resource{Tenant: tenant, Type: "storage.object"}
	var attrs []byte
	var label, floor, kind string
	err := s.pool.QueryRow(ctx, `
		SELECT i.object::text, i.planned_scope, i.planned_attributes, i.label, b.default_label, i.kind
		  FROM upload_intents i JOIN buckets b ON b.tenant = i.tenant AND b.id = i.bucket
		 WHERE i.tenant = $1 AND i.id::text = $2 AND i.new_object AND i.state IN ('RESERVED', 'STAGED')`, tenant, intent).
		Scan(&r.ID, &r.Scope, &attrs, &label, &floor, &kind)
	switch kind {
	case "unit":
		r.Type = "document.text_unit"
	case "derived":
		r.Type = "document.derived"
	case "original":
		// An original has no resource of its own (CNT-003).
		return registry.Resource{}, registry.ErrUnknownResource
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return registry.Resource{}, registry.ErrUnknownResource
	}
	if err != nil {
		return registry.Resource{}, err
	}
	if err := json.Unmarshal(attrs, &r.Attributes); err != nil {
		return registry.Resource{}, err
	}
	// The entries of a text collection are text.entry resources (DOC-005).
	if entry, _ := r.Attributes["entry"].(bool); entry && r.Type == "document.text_unit" {
		r.Type = "text.entry"
	}
	// An explicit label is a proposed change like a relabel: policies see
	// it as new_label beside the collection floor (LAB-002).
	if label != "" {
		r.Attributes["new_label"], r.Attributes["floor"] = label, floor
	}
	return r, nil
}

// plannedDocumentVersion is the document version an open document intent
// will publish, with the attributes assigned at begin.
func (s *Store) plannedDocumentVersion(ctx context.Context, tenant, intent string) (registry.Resource, error) {
	r := registry.Resource{Tenant: tenant, Type: "document.version"}
	var attrs []byte
	err := s.pool.QueryRow(ctx, `
		SELECT document_version::text, planned_scope, planned_attributes FROM document_intents
		 WHERE tenant = $1 AND id::text = $2 AND state = 'RESERVED'`, tenant, intent).Scan(&r.ID, &r.Scope, &attrs)
	if errors.Is(err, pgx.ErrNoRows) {
		return registry.Resource{}, registry.ErrUnknownResource
	}
	if err != nil {
		return registry.Resource{}, err
	}
	return r, json.Unmarshal(attrs, &r.Attributes)
}
