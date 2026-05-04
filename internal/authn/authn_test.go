package authn

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
)

type fakeAuth struct {
	name string
	id   Identity
	err  error
}

func (f *fakeAuth) Name() string                                    { return f.name }
func (f *fakeAuth) Authenticate(_ context.Context) (Identity, error) { return f.id, f.err }

func TestRegistry_RegisterAndCreate(t *testing.T) {
	t.Parallel()

	r := NewRegistry()
	err := r.Register("test", func(cfg json.RawMessage) (Authenticator, error) {
		return &fakeAuth{name: "test", id: Identity{Name: "admin"}}, nil
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	auth, err := r.Create("test", nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if auth.Name() != "test" {
		t.Errorf("Name = %q", auth.Name())
	}
}

func TestRegistry_DuplicateRegister(t *testing.T) {
	t.Parallel()

	r := NewRegistry()
	factory := func(cfg json.RawMessage) (Authenticator, error) {
		return &fakeAuth{name: "dup"}, nil
	}
	r.Register("dup", factory)

	err := r.Register("dup", factory)
	if err == nil {
		t.Error("expected error for duplicate registration")
	}
}

func TestRegistry_UnknownProvider(t *testing.T) {
	t.Parallel()

	r := NewRegistry()
	_, err := r.Create("nonexistent", nil)
	if err == nil {
		t.Error("expected error for unknown provider")
	}
}

func TestRegistry_Names(t *testing.T) {
	t.Parallel()

	r := NewRegistry()
	r.Register("a", func(json.RawMessage) (Authenticator, error) { return &fakeAuth{}, nil })
	r.Register("b", func(json.RawMessage) (Authenticator, error) { return &fakeAuth{}, nil })

	names := r.Names()
	if len(names) != 2 {
		t.Errorf("Names = %v, want 2", names)
	}
}

func TestIdentityContext(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	_, ok := IdentityFromContext(ctx)
	if ok {
		t.Error("expected no identity in empty context")
	}

	id := Identity{
		Name:   "admin",
		Groups: []string{"operators"},
		Meta:   map[string]string{"provider": "mtls"},
	}
	ctx = ContextWithIdentity(ctx, id)

	got, ok := IdentityFromContext(ctx)
	if !ok {
		t.Fatal("expected identity in context")
	}
	if got.Name != "admin" {
		t.Errorf("Name = %q", got.Name)
	}
	if len(got.Groups) != 1 || got.Groups[0] != "operators" {
		t.Errorf("Groups = %v", got.Groups)
	}
	if got.Meta["provider"] != "mtls" {
		t.Errorf("Meta = %v", got.Meta)
	}
}

func TestRegistry_FactoryError(t *testing.T) {
	t.Parallel()

	r := NewRegistry()
	r.Register("broken", func(json.RawMessage) (Authenticator, error) {
		return nil, fmt.Errorf("config invalid")
	})

	_, err := r.Create("broken", nil)
	if err == nil {
		t.Error("expected error from broken factory")
	}
}
