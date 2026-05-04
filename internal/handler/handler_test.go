package handler

import (
	"context"
	"fmt"
	"testing"

	"github.com/rsturla/hbctl/internal/authn"
	"github.com/rsturla/hbctl/internal/authz"
)

type fakeAuthorizer struct {
	decision     authz.Decision
	err          error
	lastAction   string
	lastResource authz.Resource
}

func (f *fakeAuthorizer) Name() string { return "fake" }
func (f *fakeAuthorizer) Authorize(_ context.Context, _ authn.Identity, action string, r authz.Resource) (authz.Decision, error) {
	f.lastAction = action
	f.lastResource = r
	return f.decision, f.err
}

func authnCtx(name string, groups ...string) context.Context {
	return authn.ContextWithIdentity(context.Background(), authn.Identity{Name: name, Groups: groups})
}

// --- Construction panic tests ---

func TestNewUnary_PanicsWithoutAction(t *testing.T) {
	t.Parallel()
	defer func() { recover() }()
	NewUnary("", func(_ *string) authz.Resource { return authz.ThisNode() }, func(_ context.Context, _ *string) (*string, error) { return nil, nil })
	t.Error("expected panic")
}

func TestNewUnary_PanicsWithoutResource(t *testing.T) {
	t.Parallel()
	defer func() { recover() }()
	NewUnary[*string, *string]("test", nil, func(_ context.Context, _ *string) (*string, error) { return nil, nil })
	t.Error("expected panic")
}

func TestNewUnary_PanicsWithoutFn(t *testing.T) {
	t.Parallel()
	defer func() { recover() }()
	NewUnary[*string, *string]("test", func(_ *string) authz.Resource { return authz.ThisNode() }, nil)
	t.Error("expected panic")
}

func TestNewServerStream_PanicsWithoutAction(t *testing.T) {
	t.Parallel()
	defer func() { recover() }()
	NewServerStream("", func(_ *string) authz.Resource { return authz.ThisNode() }, func(_ context.Context, _ *string, _ func(*string) error) error { return nil })
	t.Error("expected panic")
}

func TestNewServerStream_PanicsWithoutResource(t *testing.T) {
	t.Parallel()
	defer func() { recover() }()
	NewServerStream[*string, *string]("test", nil, func(_ context.Context, _ *string, _ func(*string) error) error { return nil })
	t.Error("expected panic")
}

func TestNewServerStream_PanicsWithoutFn(t *testing.T) {
	t.Parallel()
	defer func() { recover() }()
	NewServerStream[*string, *string]("test", func(_ *string) authz.Resource { return authz.ThisNode() }, nil)
	t.Error("expected panic")
}

// --- Execute tests (the critical auth path) ---

func TestExecute_NoIdentity_Rejected(t *testing.T) {
	t.Parallel()

	h := NewReadOnly("Test", func(_ context.Context, req *string) (*string, error) {
		t.Error("handler should not be called without identity")
		return nil, nil
	})

	_, err := h.Execute(context.Background(), nil, strPtr("req"))
	if err == nil {
		t.Fatal("expected error for missing identity")
	}
}

func TestExecute_WithIdentity_NilAuthz_Denied(t *testing.T) {
	t.Parallel()

	h := NewReadOnly("Test", func(_ context.Context, req *string) (*string, error) {
		t.Error("handler should not be called with nil authorizer")
		return nil, nil
	})

	_, err := h.Execute(authnCtx("admin"), nil, strPtr("req"))
	if err == nil {
		t.Fatal("expected error — nil authorizer should deny")
	}
}

func TestExecute_AuthzAllow(t *testing.T) {
	t.Parallel()

	az := &fakeAuthorizer{decision: authz.Allow}
	h := NewUnary("Upgrade",
		func(req *string) authz.Resource { return authz.ImageResource(*req) },
		func(_ context.Context, req *string) (*string, error) { return strPtr("done"), nil },
	)

	resp, err := h.Execute(authnCtx("admin"), az, strPtr("registry.example.com/os:v2"))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if *resp != "done" {
		t.Errorf("resp = %q", *resp)
	}
	if az.lastAction != "Upgrade" {
		t.Errorf("action = %q", az.lastAction)
	}
	if az.lastResource.Type != authz.ResourceImage {
		t.Errorf("resource type = %q", az.lastResource.Type)
	}
	if az.lastResource.ID != "registry.example.com/os:v2" {
		t.Errorf("resource ID = %q", az.lastResource.ID)
	}
}

func TestExecute_AuthzDeny(t *testing.T) {
	t.Parallel()

	az := &fakeAuthorizer{decision: authz.Deny}
	h := NewUnary("Reboot",
		func(_ *string) authz.Resource { return authz.NodeResource("*") },
		func(_ context.Context, _ *string) (*string, error) {
			t.Error("handler should not be called when denied")
			return nil, nil
		},
	)

	_, err := h.Execute(authnCtx("readonly-user"), az, strPtr(""))
	if err == nil {
		t.Fatal("expected error for denied access")
	}
}

func TestExecute_AuthzError(t *testing.T) {
	t.Parallel()

	az := &fakeAuthorizer{err: fmt.Errorf("policy engine error")}
	h := NewReadOnly("Stats", func(_ context.Context, _ *string) (*string, error) {
		t.Error("handler should not be called on authz error")
		return nil, nil
	})

	_, err := h.Execute(authnCtx("admin"), az, strPtr(""))
	if err == nil {
		t.Fatal("expected error for authz failure")
	}
}

func TestExecute_ResourcePassedToAuthz(t *testing.T) {
	t.Parallel()

	az := &fakeAuthorizer{decision: authz.Allow}
	h := NewUnary("ServiceControl",
		func(req *string) authz.Resource { return authz.ServiceResource(*req) },
		func(_ context.Context, _ *string) (*string, error) { return strPtr("ok"), nil },
	)

	h.Execute(authnCtx("admin"), az, strPtr("crio.service"))

	if az.lastResource.Type != authz.ResourceService {
		t.Errorf("resource type = %q, want Service", az.lastResource.Type)
	}
	if az.lastResource.ID != "crio.service" {
		t.Errorf("resource ID = %q", az.lastResource.ID)
	}
}

func TestExecute_InvalidResource_Rejected(t *testing.T) {
	t.Parallel()

	h := NewUnary("Bad",
		func(_ *string) authz.Resource { return authz.Resource{} },
		func(_ context.Context, _ *string) (*string, error) {
			t.Error("handler should not be called with invalid resource")
			return nil, nil
		},
	)

	_, err := h.Execute(authnCtx("admin"), nil, strPtr(""))
	if err == nil {
		t.Fatal("expected error for invalid resource")
	}
}

// --- ServerStream Execute tests ---

func TestStreamExecute_NoIdentity_Rejected(t *testing.T) {
	t.Parallel()

	h := NewReadOnlyStream("Logs", func(_ context.Context, _ *string, _ func(*string) error) error {
		t.Error("should not be called")
		return nil
	})

	err := h.Execute(context.Background(), nil, strPtr(""), func(_ *string) error { return nil })
	if err == nil {
		t.Fatal("expected error for missing identity")
	}
}

func TestStreamExecute_AuthzDeny(t *testing.T) {
	t.Parallel()

	az := &fakeAuthorizer{decision: authz.Deny}
	h := NewReadOnlyStream("Logs", func(_ context.Context, _ *string, _ func(*string) error) error {
		t.Error("should not be called when denied")
		return nil
	})

	err := h.Execute(authnCtx("user"), az, strPtr(""), func(_ *string) error { return nil })
	if err == nil {
		t.Fatal("expected error for denied")
	}
}

func TestStreamExecute_AuthzAllow(t *testing.T) {
	t.Parallel()

	az := &fakeAuthorizer{decision: authz.Allow}
	called := false
	h := NewReadOnlyStream("Logs", func(_ context.Context, _ *string, send func(*string) error) error {
		called = true
		return send(strPtr("log line"))
	})

	var received string
	err := h.Execute(authnCtx("admin"), az, strPtr(""), func(s *string) error {
		received = *s
		return nil
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !called {
		t.Error("handler not called")
	}
	if received != "log line" {
		t.Errorf("received = %q", received)
	}
}

// --- ReadOnly helpers ---

func TestNewReadOnly_ResourceIsThisNode(t *testing.T) {
	t.Parallel()

	az := &fakeAuthorizer{decision: authz.Allow}
	h := NewReadOnly("Version", func(_ context.Context, _ *string) (*string, error) {
		return strPtr("ok"), nil
	})

	h.Execute(authnCtx("user"), az, strPtr(""))

	if az.lastResource.Type != authz.ResourceNode || az.lastResource.ID != "*" {
		t.Errorf("ReadOnly resource = %s, want Node::*", az.lastResource)
	}
}

func strPtr(s string) *string { return &s }
