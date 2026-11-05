// Package adminapi serves the admin API of fga-admin serve: the directory
// changes of package adminops, and read-only views of the directory, the
// policy bundle and recent audit events, for an administration console
// that may run on another machine. Every request comes from a configured
// console, identified by its client certificate, and carries the token of
// an administrator of the tenant it acts on; administrators are named in
// the configuration only, so no request can make one (ADM-002). The API
// reads no content: an administrator is not a data reader (ADM-001).
package adminapi

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"fga/internal/adminops"
	"fga/internal/audit"
	"fga/internal/authn"
	"fga/internal/catalog"
	"fga/internal/datatools"
	"fga/internal/delegation"
	"fga/internal/jsonunits"
	"fga/internal/release"
	"fga/internal/sources"
	"fga/internal/strictjson"
)

// TokenVerifier verifies an administrator's access token.
type TokenVerifier interface {
	Verify(token, audience string) (authn.Claims, error)
}

// Config is what the admin API serves with.
type Config struct {
	Ops      adminops.Ops
	Tokens   TokenVerifier
	Audience string
	// Admins lists the administrators' token subjects per tenant.
	Admins map[string][]string
	// Consoles are the client identities allowed to call; ConsoleOf
	// identifies the caller of a request.
	Consoles  []string
	ConsoleOf func(*http.Request) (string, error)
	// Policy reads the policy bundle the console shows.
	Policy func() (Policy, error)
	Logger *slog.Logger
}

const (
	maxBody      = 64 << 10
	defaultLimit = 100
	maxLimit     = 500
	maxEvents    = 200
)

type server struct{ Config }

// caller is the console and administrator of a request.
type caller struct {
	tenant, subject, console string
}

func (c caller) who() adminops.Who {
	return adminops.Who{Actor: c.subject, Via: "console " + c.console}
}

// Handler returns the admin API.
func Handler(c Config) http.Handler {
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	s := &server{c}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	route := func(pattern string, h func(http.ResponseWriter, *http.Request, caller)) {
		mux.HandleFunc(pattern, s.auth(h))
	}
	route("GET /v1/admin/whoami", s.whoami)
	route("GET /v1/admin/identities", s.listIdentities)
	route("PUT /v1/admin/identities/{id}", s.putIdentity)
	route("POST /v1/admin/identities/{id}/disable", s.disableIdentity)
	route("POST /v1/admin/identities/{id}/capabilities/grant", s.grant)
	route("POST /v1/admin/identities/{id}/capabilities/revoke", s.revoke)
	route("GET /v1/admin/identities/{id}/sign-in-keys", s.listSignInKeys)
	route("POST /v1/admin/identities/{id}/sign-in-keys", s.addSignInKey)
	route("POST /v1/admin/identities/{id}/sign-in-keys/{fp}/remove", s.removeSignInKey)
	route("GET /v1/admin/delegations", s.listDelegations)
	route("POST /v1/admin/delegations", s.addDelegation)
	route("POST /v1/admin/delegations/{id}/revoke", s.revokeDelegation)
	route("GET /v1/admin/buckets", s.listBuckets)
	route("POST /v1/admin/buckets", s.createBucket)
	route("POST /v1/admin/mcp/enable", s.enableMCP)
	route("GET /v1/admin/sources", s.listSources)
	route("POST /v1/admin/sources", s.addSource)
	route("PUT /v1/admin/sources/{id}", s.putSource)
	route("POST /v1/admin/sources/{id}/try", s.trySource)
	route("POST /v1/admin/sources/{id}/review", s.reviewSource)
	route("POST /v1/admin/sources/{id}/disable", s.disableSource)
	route("GET /v1/admin/data-tools", s.listDataTools)
	route("POST /v1/admin/data-tools", s.putDataTool)
	route("PUT /v1/admin/data-tools/{id}", s.putDataTool)
	route("POST /v1/admin/data-tools/{id}/review", s.reviewDataTool)
	route("POST /v1/admin/data-tools/{id}/disable", s.disableDataTool)
	route("GET /v1/admin/policy", s.policy)
	route("GET /v1/admin/events", s.events)
	return mux
}

// auth admits a request from a configured console with an administrator's
// token, and acts in the token's tenant only.
func (s *server) auth(h func(http.ResponseWriter, *http.Request, caller)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		console, err := s.ConsoleOf(r)
		if err != nil || !slices.Contains(s.Consoles, console) {
			s.Logger.Warn("admin API: refused a caller that is not a configured console", "console", console, "path", r.URL.Path)
			writeError(w, http.StatusForbidden, "not a configured console")
			return
		}
		token, ok := authn.Bearer(r.Header.Get("Authorization"))
		if !ok {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeError(w, http.StatusUnauthorized, "an administrator's bearer token is required")
			return
		}
		claims, err := s.Tokens.Verify(token, s.Audience)
		if err != nil {
			s.Logger.Warn("admin API: refused a token", "console", console, "error", err)
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			writeError(w, http.StatusUnauthorized, "the token does not verify")
			return
		}
		if !slices.Contains(s.Admins[claims.Tenant], claims.Subject) {
			s.Logger.Warn("admin API: refused a subject that is not an administrator", "console", console, "tenant", claims.Tenant,
				"subject", claims.Subject, "path", r.URL.Path)
			writeError(w, http.StatusForbidden, "not an administrator of this tenant")
			return
		}
		h(w, r, caller{tenant: claims.Tenant, subject: claims.Subject, console: console})
	}
}

func (s *server) whoami(w http.ResponseWriter, _ *http.Request, c caller) {
	writeJSON(w, http.StatusOK, map[string]string{"tenant": c.tenant, "subject": c.subject, "console": c.console})
}

// page reads the after and limit query parameters of a list.
func page(r *http.Request) (string, int, error) {
	limit := defaultLimit
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > maxLimit {
			return "", 0, adminops.ErrInvalid
		}
		limit = n
	}
	return r.URL.Query().Get("after"), limit, nil
}

// list answers a page of items; next is set when there may be more.
func list[T any](w http.ResponseWriter, items []T, limit int, key func(T) string) {
	out := map[string]any{"items": items}
	if len(items) == limit {
		out["next"] = key(items[len(items)-1])
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) listIdentities(w http.ResponseWriter, r *http.Request, c caller) {
	after, limit, err := page(r)
	if err != nil {
		s.fail(w, err)
		return
	}
	items, err := s.Ops.Store.ListIdentities(r.Context(), c.tenant, after, limit)
	if err != nil {
		s.fail(w, err)
		return
	}
	list(w, items, limit, func(i catalog.IdentityRecord) string { return i.ID })
}

func (s *server) putIdentity(w http.ResponseWriter, r *http.Request, c caller) {
	var body struct {
		Roles      []string       `json:"roles"`
		Attributes map[string]any `json:"attributes"`
	}
	if !s.decode(w, r, &body) {
		return
	}
	if err := s.Ops.PutIdentity(r.Context(), c.who(), c.tenant, r.PathValue("id"), body.Roles, body.Attributes); err != nil {
		s.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) disableIdentity(w http.ResponseWriter, r *http.Request, c caller) {
	// The body is optional: {"confirm_unreadable": true} disables an
	// identity that is the last reader of client-mode files.
	var body struct {
		ConfirmUnreadable bool `json:"confirm_unreadable"`
	}
	if !s.decodeOptional(w, r, &body) {
		return
	}
	if err := s.Ops.DisableIdentity(r.Context(), c.who(), c.tenant, r.PathValue("id"), body.ConfirmUnreadable); err != nil {
		s.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// capabilities reads a grant or revoke body: a preset or actions per type.
func (s *server) capabilities(w http.ResponseWriter, r *http.Request) (map[string][]string, bool) {
	var body struct {
		Preset       string              `json:"preset"`
		Capabilities map[string][]string `json:"capabilities"`
	}
	if !s.decode(w, r, &body) {
		return nil, false
	}
	caps, err := adminops.Capabilities(body.Preset, body.Capabilities)
	if err != nil {
		s.fail(w, err)
		return nil, false
	}
	return caps, true
}

func (s *server) grant(w http.ResponseWriter, r *http.Request, c caller) {
	caps, ok := s.capabilities(w, r)
	if !ok {
		return
	}
	if err := s.Ops.Grant(r.Context(), c.who(), c.tenant, r.PathValue("id"), caps); err != nil {
		s.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) revoke(w http.ResponseWriter, r *http.Request, c caller) {
	caps, ok := s.capabilities(w, r)
	if !ok {
		return
	}
	held, err := s.Ops.Revoke(r.Context(), c.who(), c.tenant, r.PathValue("id"), caps)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"revoked": held})
}

func (s *server) listDelegations(w http.ResponseWriter, r *http.Request, c caller) {
	after, limit, err := page(r)
	if err != nil {
		s.fail(w, err)
		return
	}
	items, err := s.Ops.Store.ListDelegations(r.Context(), c.tenant, after, limit)
	if err != nil {
		s.fail(w, err)
		return
	}
	list(w, items, limit, func(d catalog.DelegationRecord) string { return d.ID })
}

func (s *server) addDelegation(w http.ResponseWriter, r *http.Request, c caller) {
	var body struct {
		ID        string              `json:"id"`
		Actor     string              `json:"actor"`
		Subject   string              `json:"subject"`
		Audience  string              `json:"audience"`
		Grants    map[string][]string `json:"grants"`
		ExpiresIn string              `json:"expires_in"`
		Parent    string              `json:"parent"`
	}
	if !s.decode(w, r, &body) {
		return
	}
	life, err := time.ParseDuration(body.ExpiresIn)
	if err != nil || life <= 0 {
		writeError(w, http.StatusBadRequest, "expires_in must be a positive Go duration, such as 24h")
		return
	}
	grants, err := adminops.Grants(body.Grants)
	if err != nil {
		s.fail(w, err)
		return
	}
	d := delegation.Delegation{ID: delegation.ID(body.ID), Tenant: c.tenant, Actor: body.Actor, Subject: body.Subject, Audience: body.Audience,
		Grants: grants, ExpiresAt: s.Ops.Now().Add(life), Parent: delegation.ID(body.Parent)}
	if err := s.Ops.AddDelegation(r.Context(), c.who(), d); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": body.ID, "expires_at": d.ExpiresAt.UTC()})
}

func (s *server) revokeDelegation(w http.ResponseWriter, r *http.Request, c caller) {
	if err := s.Ops.RevokeDelegation(r.Context(), c.who(), c.tenant, r.PathValue("id")); err != nil {
		s.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// bucketJSON is a bucket's protected defaults on the wire. Source names
// the source that owns the bucket; only adding a source sets it.
type bucketJSON struct {
	Name       string `json:"name"`
	Project    string `json:"project"`
	Label      string `json:"label"`
	Scope      string `json:"scope"`
	Encryption string `json:"encryption"`
	Source     string `json:"source,omitempty"`
}

func (s *server) listBuckets(w http.ResponseWriter, r *http.Request, c caller) {
	after, limit, err := page(r)
	if err != nil {
		s.fail(w, err)
		return
	}
	buckets, err := s.Ops.Store.ListBuckets(r.Context(), c.tenant, after, limit)
	if err != nil {
		s.fail(w, err)
		return
	}
	items := make([]bucketJSON, len(buckets))
	for i, b := range buckets {
		items[i] = bucketJSON{Name: b.Name, Project: b.Project, Label: b.Label, Scope: b.Scope, Encryption: b.Encryption, Source: b.Source}
	}
	list(w, items, limit, func(b bucketJSON) string { return b.Name })
}

func (s *server) createBucket(w http.ResponseWriter, r *http.Request, c caller) {
	// The defaults are fga-admin bucket create's.
	body := bucketJSON{Label: "internal", Encryption: "server"}
	if !s.decode(w, r, &body) {
		return
	}
	if body.Source != "" {
		s.fail(w, adminops.ErrInvalid)
		return
	}
	id, err := s.Ops.CreateBucket(r.Context(), c.who(), c.tenant, catalog.Bucket{Name: body.Name, Project: body.Project, Label: body.Label,
		Scope: body.Scope, Encryption: body.Encryption})
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"id": id.String(), "name": body.Name, "encryption": body.Encryption})
}

func (s *server) listSources(w http.ResponseWriter, r *http.Request, c caller) {
	after, limit, err := page(r)
	if err != nil {
		s.fail(w, err)
		return
	}
	items, err := s.Ops.Store.ListSources(r.Context(), c.tenant, after, limit)
	if err != nil {
		s.fail(w, err)
		return
	}
	list(w, items, limit, func(src catalog.Source) string { return src.ID })
}

// versionJSON answers a stored version of a source or a data tool.
func versionJSON(id string, v catalog.RecordVersion) map[string]any {
	return map[string]any{"id": id, "version": v.Version, "state": v.State, "digest": v.Digest}
}

func (s *server) addSource(w http.ResponseWriter, r *http.Request, c caller) {
	body := struct {
		Bucket bucketJSON      `json:"bucket"`
		Source json.RawMessage `json:"source"`
	}{Bucket: bucketJSON{Label: "internal", Encryption: "server"}}
	if !s.decode(w, r, &body) {
		return
	}
	def, err := sources.Parse(body.Source)
	if err != nil || body.Bucket.Source != "" {
		s.fail(w, errors.Join(adminops.ErrInvalid, err))
		return
	}
	v, err := s.Ops.AddSource(r.Context(), c.who(), c.tenant, catalog.Bucket{Name: body.Bucket.Name, Project: body.Bucket.Project,
		Label: body.Bucket.Label, Scope: body.Bucket.Scope, Encryption: body.Bucket.Encryption}, def)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, versionJSON(def.ID, v))
}

func (s *server) putSource(w http.ResponseWriter, r *http.Request, c caller) {
	var raw json.RawMessage
	if !s.decode(w, r, &raw) {
		return
	}
	def, err := sources.Parse(raw)
	if err == nil && def.ID != r.PathValue("id") {
		err = errors.New("the record's id is not the source's")
	}
	if err != nil {
		s.fail(w, errors.Join(adminops.ErrInvalid, err))
		return
	}
	v, err := s.Ops.PutSource(r.Context(), c.who(), c.tenant, def)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, versionJSON(def.ID, v))
}

// trySource splits a sample payload the administrator sends. A refusal
// answers the profile's reason and the parser's own words, which may quote
// the sample: it is the administrator's.
func (s *server) trySource(w http.ResponseWriter, r *http.Request, c caller) {
	var body struct {
		Version   int             `json:"version,omitempty"`
		Principal string          `json:"principal,omitempty"`
		Payload   json.RawMessage `json:"payload"`
	}
	if !s.decode(w, r, &body) {
		return
	}
	reading, err := s.Ops.TrySource(r.Context(), c.tenant, r.PathValue("id"), body.Version, body.Payload, body.Principal)
	var refused *jsonunits.ReadingError
	if errors.As(err, &refused) {
		out := map[string]any{"refused": refused.Reason}
		if refused.Pointer != "" {
			out["pointer"] = refused.Pointer
		}
		if cause := errors.Unwrap(refused); cause != nil {
			out["detail"] = cause.Error()
		}
		writeJSON(w, http.StatusOK, out)
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	units := make([]string, len(reading.Units))
	for i, u := range reading.Units {
		units[i] = string(u)
	}
	writeJSON(w, http.StatusOK, map[string]any{"key": reading.Key, "units": units, "fields": reading.Fields})
}

func (s *server) reviewSource(w http.ResponseWriter, r *http.Request, c caller) {
	var body struct {
		Version int    `json:"version"`
		Digest  string `json:"digest"`
	}
	if !s.decode(w, r, &body) {
		return
	}
	v, err := s.Ops.ReviewSource(r.Context(), c.who(), c.tenant, r.PathValue("id"), body.Version, body.Digest)
	if err != nil {
		s.fail(w, err)
		return
	}
	out := versionJSON(r.PathValue("id"), v)
	// The review is committed; tools it breaks are reported, not refused.
	if broken, err := s.Ops.BrokenDataTools(r.Context(), c.tenant, r.PathValue("id")); err != nil {
		s.Logger.Error("admin API: listing the data tools a source review breaks", "error", err)
	} else if len(broken) > 0 {
		out["breaks_data_tools"] = broken
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) listDataTools(w http.ResponseWriter, r *http.Request, c caller) {
	after, limit, err := page(r)
	if err != nil {
		s.fail(w, err)
		return
	}
	items, err := s.Ops.Store.ListDataTools(r.Context(), c.tenant, r.URL.Query().Get("source"), after, limit)
	if err != nil {
		s.fail(w, err)
		return
	}
	list(w, items, limit, func(t catalog.DataTool) string { return t.Name })
}

// putDataTool adds a data tool with its draft version 1 (POST) or stores
// its next version as the draft (PUT); the body is the record.
func (s *server) putDataTool(w http.ResponseWriter, r *http.Request, c caller) {
	var raw json.RawMessage
	if !s.decode(w, r, &raw) {
		return
	}
	add := r.Method == http.MethodPost
	def, err := datatools.Parse(raw)
	if err == nil && !add && def.Name != r.PathValue("id") {
		err = errors.New("the record's name is not the tool's")
	}
	if err != nil {
		s.fail(w, errors.Join(adminops.ErrInvalid, err))
		return
	}
	v, status := catalog.RecordVersion{}, http.StatusOK
	if add {
		v, err = s.Ops.AddDataTool(r.Context(), c.who(), c.tenant, def)
		status = http.StatusCreated
	} else {
		v, err = s.Ops.PutDataTool(r.Context(), c.who(), c.tenant, def)
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, status, versionJSON(def.Name, v))
}

func (s *server) reviewDataTool(w http.ResponseWriter, r *http.Request, c caller) {
	var body struct {
		Version int    `json:"version"`
		Digest  string `json:"digest"`
	}
	if !s.decode(w, r, &body) {
		return
	}
	v, err := s.Ops.ReviewDataTool(r.Context(), c.who(), c.tenant, r.PathValue("id"), body.Version, body.Digest)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, versionJSON(r.PathValue("id"), v))
}

func (s *server) disableDataTool(w http.ResponseWriter, r *http.Request, c caller) {
	if err := s.Ops.DisableDataTool(r.Context(), c.who(), c.tenant, r.PathValue("id")); err != nil {
		s.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) disableSource(w http.ResponseWriter, r *http.Request, c caller) {
	if err := s.Ops.DisableSource(r.Context(), c.who(), c.tenant, r.PathValue("id")); err != nil {
		s.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) enableMCP(w http.ResponseWriter, r *http.Request, c caller) {
	if err := s.Ops.EnableMCP(r.Context(), c.who(), c.tenant); err != nil {
		s.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) policy(w http.ResponseWriter, _ *http.Request, _ caller) {
	if s.Policy == nil {
		writeError(w, http.StatusNotFound, "no policy bundle is configured")
		return
	}
	p, err := s.Policy()
	if err != nil {
		s.Logger.Error("admin API: policy bundle", "error", err)
		writeError(w, http.StatusServiceUnavailable, "the policy bundle cannot be read or does not verify")
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *server) events(w http.ResponseWriter, r *http.Request, c caller) {
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > maxEvents {
			s.fail(w, adminops.ErrInvalid)
			return
		}
		limit = n
	}
	items, err := s.Ops.Store.RecentEvents(r.Context(), c.tenant, limit)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// Policy is the signed bundle in the configured directory, its signature
// verified with the trusted publisher keys. It is read-only: rule changes
// are signed offline and activated by restarting fga-decision with them,
// so the publisher's private key never reaches this server.
type Policy struct {
	Epoch           uint64                     `json:"epoch"`
	KeyID           string                     `json:"key_id"`
	Digest          string                     `json:"digest"`
	LabelOrder      []string                   `json:"label_order"`
	LabelGeneration uint64                     `json:"label_generation"`
	Business        []string                   `json:"business"`
	Ceiling         []string                   `json:"ceiling"`
	Documents       map[string]json.RawMessage `json:"documents"`
}

// LoadPolicy reads the bundle in dir and verifies its signature.
func LoadPolicy(dir string, publishers map[string]ed25519.PublicKey) (Policy, error) {
	b, _, err := release.LoadBundle(dir)
	if err != nil {
		return Policy{}, err
	}
	digest, err := b.Digest()
	if err != nil {
		return Policy{}, err
	}
	key, ok := publishers[b.KeyID]
	if !ok || !ed25519.Verify(key, release.SigningBytes(b.Epoch, digest), b.Signature) {
		return Policy{}, errors.New("adminapi: the bundle's signature does not verify with a trusted publisher key")
	}
	docs := map[string]json.RawMessage{}
	for name, raw := range b.Documents {
		if !json.Valid(raw) {
			return Policy{}, errors.New("adminapi: bundle document " + name + " is not JSON")
		}
		docs[name] = raw
	}
	return Policy{Epoch: b.Epoch, KeyID: b.KeyID, Digest: digest, LabelOrder: b.Info.LabelOrder, LabelGeneration: b.Info.LabelGeneration,
		Business: b.Info.Business, Ceiling: b.Ceiling, Documents: docs}, nil
}

// decode reads a JSON request body strictly; on failure it answers 400.
func (s *server) decode(w http.ResponseWriter, r *http.Request, v any) bool {
	return s.decodeBody(w, r, v, false)
}

// decodeOptional is decode for a body that may be empty, leaving v as is.
func (s *server) decodeOptional(w http.ResponseWriter, r *http.Request, v any) bool {
	return s.decodeBody(w, r, v, true)
}

func (s *server) decodeBody(w http.ResponseWriter, r *http.Request, v any, optional bool) bool {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err == nil && (!optional || len(bytes.TrimSpace(raw)) > 0) {
		err = strictjson.Decode(raw, v)
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, "the request body is not the expected JSON: "+err.Error())
		return false
	}
	return true
}

// fail answers an error from a change or a read.
func (s *server) fail(w http.ResponseWriter, err error) {
	var pg *pgconn.PgError
	var last *catalog.LastReaderError
	switch {
	case errors.As(err, &last):
		writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error() + `; send {"confirm_unreadable": true} to make the change anyway`,
			"unreadable": last.Unreadable})
	case errors.Is(err, adminops.ErrInvalid), errors.Is(err, catalog.ErrBadDelegation):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, catalog.ErrNoRow):
		writeError(w, http.StatusNotFound, "no such identity, delegation, source, data tool or sign-in key")
	case errors.Is(err, catalog.ErrSelfReview):
		writeError(w, http.StatusForbidden, "the author of a draft cannot review it; another administrator does")
	case errors.Is(err, catalog.ErrDraftConflict), errors.Is(err, catalog.ErrDisabled):
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, catalog.ErrDelegationExists):
		writeError(w, http.StatusConflict, "a delegation with this ID exists; delegations are revoked and replaced, never changed")
	case errors.Is(err, catalog.ErrNoJournal), errors.Is(err, catalog.ErrJournalMismatch):
		s.Logger.Error("admin API: security journal", "error", err)
		writeError(w, http.StatusServiceUnavailable, "the security journal is not available; changes it must record are refused")
	case errors.Is(err, audit.ErrFull):
		s.Logger.Error("admin API: audit outbox", "error", err)
		writeError(w, http.StatusServiceUnavailable, "the audit outbox is full; changes resume once its events are exported")
	case errors.As(err, &pg) && pg.Code == "23505":
		writeError(w, http.StatusConflict, "it exists already")
	case errors.As(err, &pg) && pg.Code == "23503":
		writeError(w, http.StatusBadRequest, "it refers to an identity or delegation that does not exist")
	default:
		s.Logger.Error("admin API", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
