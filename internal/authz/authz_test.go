package authz

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/rsturla/hbctl/internal/authn"
)

type fakeAuthorizer struct {
	decision Decision
	err      error
}

func (f *fakeAuthorizer) Name() string { return "fake" }
func (f *fakeAuthorizer) Authorize(_ context.Context, _ authn.Identity, _ string, _ Resource) (Decision, error) {
	return f.decision, f.err
}

func TestRegistry_RegisterAndCreate(t *testing.T) {
	t.Parallel()

	r := NewRegistry()
	r.Register("test", func(json.RawMessage) (Authorizer, error) {
		return &fakeAuthorizer{decision: Allow}, nil
	})

	az, err := r.Create("test", nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if az.Name() != "fake" {
		t.Errorf("Name = %q", az.Name())
	}
}

func TestRegistry_DuplicateRegister(t *testing.T) {
	t.Parallel()

	r := NewRegistry()
	r.Register("dup", func(json.RawMessage) (Authorizer, error) { return &fakeAuthorizer{}, nil })
	err := r.Register("dup", func(json.RawMessage) (Authorizer, error) { return &fakeAuthorizer{}, nil })
	if err == nil {
		t.Error("expected error for duplicate")
	}
}

func TestRegistry_Unknown(t *testing.T) {
	t.Parallel()

	r := NewRegistry()
	_, err := r.Create("nope", nil)
	if err == nil {
		t.Error("expected error for unknown")
	}
}

func TestAllowAll(t *testing.T) {
	t.Parallel()

	az, _ := NewAllowAll(nil)
	d, err := az.Authorize(context.Background(), authn.Identity{Name: "anyone"}, "/any.Method", ThisNode())
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if d != Allow {
		t.Error("AllowAll should allow")
	}
}

func TestDecisionConstants(t *testing.T) {
	t.Parallel()

	if Deny != 0 {
		t.Errorf("Deny = %d", Deny)
	}
	if Allow != 1 {
		t.Errorf("Allow = %d", Allow)
	}
}

func TestRegistry_FactoryError(t *testing.T) {
	t.Parallel()

	r := NewRegistry()
	r.Register("broken", func(json.RawMessage) (Authorizer, error) {
		return nil, fmt.Errorf("bad config")
	})

	_, err := r.Create("broken", nil)
	if err == nil {
		t.Error("expected error from factory")
	}
}
