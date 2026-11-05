package adminops

import (
	"context"
	"crypto/ed25519"
	"errors"
	"regexp"

	"fga/internal/authn"
	"fga/internal/catalog"
	"fga/internal/cryptowire"
)

// A label names where a sign-in key is used, such as "Dana's laptop,
// browser" or "greenhouse sensor 1".
var keyLabel = regexp.MustCompile(`^[^\x00-\x1f\x7f]{1,100}$`)

// AddSignInKey registers an Ed25519 public key as a sign-in key of an
// account, with limits below the account's rights
// (docs/design/sign-in-keys.md). The administrator checks the key's
// fingerprint with its owner first. It returns the fingerprint.
func (o Ops) AddSignInKey(ctx context.Context, who Who, tenant, principal string, public []byte, label string, limits authn.KeyLimits) (string, error) {
	if err := checkID("identity", principal); err != nil {
		return "", err
	}
	if len(public) != ed25519.PublicKeySize || !cryptowire.ValidEd25519PublicKey(public) {
		return "", invalid("not a usable Ed25519 public key")
	}
	if !keyLabel.MatchString(label) {
		return "", invalid("a key's label is 1 to 100 printable characters")
	}
	if err := limits.Validate(); err != nil {
		return "", invalid("%v", err)
	}
	fp := cryptowire.SignInKeyFingerprint(public).String()
	var out string
	err := o.Store.Administer(ctx, o.event(tenant, who, "sign-in-key.add", "sign-in-key", fp), o.journal(), func(a *catalog.Admin) error {
		var err error
		out, err = a.AddSignInKey(ctx, tenant, principal, public, label, limits)
		return err
	})
	switch {
	case errors.Is(err, catalog.ErrSignInKeyExists):
		return "", invalid("this key is registered already; a removed key is never registered again")
	case errors.Is(err, catalog.ErrIdentityDisabled):
		return "", invalid("%s is disabled", principal)
	}
	return out, err
}

// RemoveSignInKey removes a sign-in key, journaled first: tokens it signs
// are refused from the next request on. It reports false when the key was
// removed already.
func (o Ops) RemoveSignInKey(ctx context.Context, who Who, tenant, principal, fingerprint string) (bool, error) {
	if err := checkID("identity", principal); err != nil {
		return false, err
	}
	if _, err := cryptowire.ParseDigest(fingerprint); err != nil {
		return false, invalid("fingerprint %q", fingerprint)
	}
	var removed bool
	err := o.Store.Administer(ctx, o.event(tenant, who, "sign-in-key.remove", "sign-in-key", fingerprint), o.journal(), func(a *catalog.Admin) error {
		var err error
		removed, err = a.RemoveSignInKey(ctx, tenant, principal, fingerprint)
		return err
	})
	return removed, err
}

// SignInKeys lists an account's sign-in keys, active and removed.
func (o Ops) SignInKeys(ctx context.Context, tenant, principal string) ([]catalog.SignInKey, error) {
	if err := checkID("identity", principal); err != nil {
		return nil, err
	}
	return o.Store.SignInKeys(ctx, tenant, principal)
}
