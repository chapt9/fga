package delegation

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"
)

var now = time.Unix(1_800_000_000, 0)

func userToAgent() Delegation {
	return Delegation{
		ID: "dlg-user", Tenant: "t-acme", Actor: "agent-7", Subject: "user-42", Audience: "tools-gw-1",
		Grants:    []Grant{{ResourceType: "document.text_unit", Actions: []string{"read", "use-in-model"}}, {ResourceType: "agent.tool", Actions: []string{AllActions}}},
		ExpiresAt: now.Add(time.Hour), Revision: 3,
	}
}

func agentToSubAgent() Delegation {
	return Delegation{
		ID: "dlg-sub", Tenant: "t-acme", Actor: "agent-9", Subject: "user-42", Audience: "tools-gw-1", Parent: "dlg-user",
		Grants:    []Grant{{ResourceType: "document.text_unit", Actions: []string{"read"}}},
		ExpiresAt: now.Add(30 * time.Minute), Revision: 1,
	}
}

func storeWith(t *testing.T, ds ...Delegation) *MemoryStore {
	t.Helper()
	s := NewMemoryStore()
	for _, d := range ds {
		if err := s.Put(d); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func TestResolveUsableChain(t *testing.T) {
	s := storeWith(t, userToAgent(), agentToSubAgent())
	chain, err := Resolve(context.Background(), s, "t-acme", "dlg-sub", now)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(chain.Revisions(), []uint64{1, 3}) {
		t.Errorf("revisions = %v, want leaf first [1 3]", chain.Revisions())
	}
	if err := chain.Admit("agent-9", "user-42", "tools-gw-1"); err != nil {
		t.Errorf("Admit: %v", err)
	}
	if !chain.Covers("document.text_unit", "read") {
		t.Error("chain should cover read")
	}
	// The parent grants use-in-model, but the child does not: every link
	// must cover the action (DLG-004).
	if chain.Covers("document.text_unit", "use-in-model") {
		t.Error("chain must not cover an action its leaf does not grant")
	}
}

func TestResolveRejectsUnusableChains(t *testing.T) {
	expired := userToAgent()
	expired.ExpiresAt = now
	otherTenant := userToAgent()
	otherTenant.Tenant = "t-other"
	// Two links with equal scope and expiry, so only the cycle is wrong.
	cycleA, cycleB := userToAgent(), userToAgent()
	cycleA.ID, cycleA.Parent, cycleB.ID, cycleB.Parent = "a", "b", "b", "a"
	deep := []Delegation{userToAgent()}
	for i := 1; i <= MaxDepth; i++ {
		d := agentToSubAgent()
		d.ID, d.Parent = ID("deep-"+string(rune('0'+i))), deep[len(deep)-1].ID
		deep = append(deep, d)
	}

	tests := []struct {
		name   string
		stored []Delegation
		tenant string
		id     ID
		want   error
	}{
		{"unknown delegation", nil, "t-acme", "dlg-user", ErrNotFound},
		{"expired (V-021)", []Delegation{expired}, "t-acme", "dlg-user", ErrExpired},
		{"stored under another tenant (DLG-007)", []Delegation{otherTenant}, "t-acme", "dlg-user", ErrNotFound},
		{"cycle", []Delegation{cycleA, cycleB}, "t-acme", "a", ErrCycle},
		{"too deep", deep, "t-acme", deep[len(deep)-1].ID, ErrTooDeep},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewMemoryStore()
			for _, d := range tt.stored {
				s.byID[memoryKey{d.Tenant, d.ID}] = d // bypass Put to store inconsistent data
			}
			if _, err := Resolve(context.Background(), s, tt.tenant, tt.id, now); !errors.Is(err, tt.want) {
				t.Fatalf("Resolve error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestRevokingParentDisablesChild(t *testing.T) {
	s := storeWith(t, userToAgent(), agentToSubAgent())
	if err := s.Revoke("t-acme", "dlg-user"); err != nil {
		t.Fatal(err)
	}
	if _, err := Resolve(context.Background(), s, "t-acme", "dlg-sub", now); !errors.Is(err, ErrRevoked) {
		t.Fatalf("Resolve error = %v, want %v", err, ErrRevoked)
	}
	d, _ := s.Get(context.Background(), "t-acme", "dlg-user")
	if d.Revision != 4 {
		t.Errorf("revision after revocation = %d, want 4 (DLG-005)", d.Revision)
	}
}

// TestChildCannotWiden covers V-022 at creation and on a chain that was
// stored inconsistently.
func TestChildCannotWiden(t *testing.T) {
	widened := agentToSubAgent()
	widened.Grants = []Grant{{ResourceType: "document.text_unit", Actions: []string{"export-key"}}}
	later := agentToSubAgent()
	later.ExpiresAt = now.Add(2 * time.Hour)
	otherSubject := agentToSubAgent()
	otherSubject.Subject = "user-99"

	for name, child := range map[string]Delegation{"wider action": widened, "later expiry": later, "other subject": otherSubject} {
		s := storeWith(t, userToAgent())
		if err := s.Put(child); !errors.Is(err, ErrWidened) {
			t.Errorf("%s: Put error = %v, want %v", name, err, ErrWidened)
		}
		s.byID[memoryKey{child.Tenant, child.ID}] = child
		if _, err := Resolve(context.Background(), s, "t-acme", child.ID, now); !errors.Is(err, ErrWidened) {
			t.Errorf("%s: Resolve error = %v, want %v", name, err, ErrWidened)
		}
	}
}

func TestAdmitChecksActorSubjectAndAudience(t *testing.T) {
	chain := Chain{userToAgent()}
	for name, tc := range map[string]struct {
		actor, subject, audience string
		want                     error
	}{
		"other actor":                 {"agent-8", "user-42", "tools-gw-1", ErrActorMismatch},
		"other subject":               {"agent-7", "user-1", "tools-gw-1", ErrSubjectMismatch},
		"other executor (V-023)":      {"agent-7", "user-42", "tools-gw-2", ErrAudienceMismatch},
		"actor, subject and audience": {"agent-7", "user-42", "tools-gw-1", nil},
	} {
		if err := chain.Admit(tc.actor, tc.subject, tc.audience); !errors.Is(err, tc.want) {
			t.Errorf("%s: Admit error = %v, want %v", name, err, tc.want)
		}
	}
}
