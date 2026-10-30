package release

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"fga/internal/policy"
	"fga/internal/strictjson"
)

// A bundle on disk is a directory with manifest.json and policies/*.json.
const (
	ManifestFile = "manifest.json"
	PoliciesDir  = "policies"
)

// Manifest is the stored form of a bundle's epoch, signature and sentinels.
type Manifest struct {
	Epoch     uint64             `json:"epoch"`
	KeyID     string             `json:"key_id"`
	Signature string             `json:"signature"`
	Sentinels []ManifestSentinel `json:"sentinels"`
}

// ManifestSentinel is the stored form of a Sentinel.
type ManifestSentinel struct {
	Name      string `json:"name"`
	Set       string `json:"set"`
	Principal struct {
		ID         string         `json:"id"`
		Roles      []string       `json:"roles"`
		Attributes map[string]any `json:"attributes"`
	} `json:"principal"`
	Resource struct {
		Type       string         `json:"type"`
		ID         string         `json:"id"`
		Scope      string         `json:"scope"`
		Attributes map[string]any `json:"attributes"`
	} `json:"resource"`
	Action string `json:"action"`
	Want   string `json:"want"`
}

// LoadBundle reads a bundle directory. The signature is read but not
// verified; Manager.Activate verifies it.
func LoadBundle(dir string) (Bundle, Manifest, error) {
	raw, err := os.ReadFile(filepath.Join(dir, ManifestFile))
	if err != nil {
		return Bundle{}, Manifest{}, err
	}
	var m Manifest
	if err := strictjson.Decode(raw, &m); err != nil {
		return Bundle{}, Manifest{}, fmt.Errorf("release: %s: %w", ManifestFile, err)
	}
	b := Bundle{Epoch: m.Epoch, KeyID: m.KeyID, Documents: map[string][]byte{}}
	if m.Signature != "" {
		if b.Signature, err = base64.StdEncoding.DecodeString(m.Signature); err != nil {
			return Bundle{}, Manifest{}, fmt.Errorf("release: signature: %w", err)
		}
	}
	files, err := filepath.Glob(filepath.Join(dir, PoliciesDir, "*.json"))
	if err != nil {
		return Bundle{}, Manifest{}, err
	}
	for _, f := range files {
		doc, err := os.ReadFile(f)
		if err != nil {
			return Bundle{}, Manifest{}, err
		}
		b.Documents[filepath.Base(f)] = doc
	}
	for _, s := range m.Sentinels {
		sentinel, err := s.sentinel()
		if err != nil {
			return Bundle{}, Manifest{}, err
		}
		b.Sentinels = append(b.Sentinels, sentinel)
	}
	return b, m, nil
}

func (s ManifestSentinel) sentinel() (Sentinel, error) {
	out := Sentinel{Name: s.Name, Request: policy.Request{
		Principal: policy.Principal{ID: s.Principal.ID, Roles: s.Principal.Roles, Attributes: s.Principal.Attributes},
		Resource:  policy.Resource{Kind: s.Resource.Type, ID: s.Resource.ID, Scope: s.Resource.Scope, Attributes: s.Resource.Attributes},
		Actions:   []string{s.Action},
	}}
	switch s.Set {
	case "business":
		out.Set = policy.SetBusiness
	case "ceiling":
		out.Set = policy.SetCeiling
	default:
		return Sentinel{}, fmt.Errorf("release: sentinel %q: unknown set %q", s.Name, s.Set)
	}
	switch strings.ToLower(s.Want) {
	case "allow":
		out.Want = policy.EffectAllow
	case "deny":
		out.Want = policy.EffectDeny
	default:
		return Sentinel{}, fmt.Errorf("release: sentinel %q: want must be allow or deny", s.Name)
	}
	return out, nil
}

// WriteManifest stores m in dir.
func WriteManifest(dir string, m Manifest) error {
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, ManifestFile), append(raw, '\n'), 0o644)
}
