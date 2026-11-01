package content

import (
	"context"
	"fmt"

	"fga/internal/catalog"
	"fga/internal/registry"
)

// Me answers the caller's own record: roles, attributes and capabilities,
// so that a console shows only what their rights allow. It is decided as
// principal.self read on the caller's own record, and answers no one
// else's. Under a delegation it is refused: an agent acting for someone
// does not read their record.
func (s *Service) Me(ctx context.Context, c Caller) (catalog.IdentityRecord, error) {
	if c.Delegation != "" {
		return catalog.IdentityRecord{}, fmt.Errorf("%w: not under a delegation", ErrInvalid)
	}
	_, rec, err := s.decide(ctx, c, registry.OpReadSelf, Audience, false,
		[]check{{id: registry.RoleSelf, role: registry.RoleSelf, action: "read", ref: planned(registry.PlannedSelf, c.Principal)}})
	if err != nil {
		return catalog.IdentityRecord{}, err
	}
	if err := s.checked(ctx, rec); err != nil {
		return catalog.IdentityRecord{}, err
	}
	return s.d.Catalog.IdentityRecordOf(ctx, c.Tenant, c.Principal)
}
