package handler

import (
	"context"
	"fmt"
	"testing"

	"github.com/rsturla/hbctl/internal/audit"
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
	defer func() { _ = recover() }()
	NewUnary("", func(_ *string) authz.Resource { return authz.ThisNode() }, func(_ context.Context, _ *string) (*string, error) { return nil, nil })
	t.Error("expected panic")
}

func TestNewUnary_PanicsWithoutResource(t *testing.T) {
	t.Parallel()
	defer func() { _ = recover() }()
	NewUnary[*string, *string]("test", nil, func(_ context.Context, _ *string) (*string, error) { return nil, nil })
	t.Error("expected panic")
}

func TestNewUnary_PanicsWithoutFn(t *testing.T) {
	t.Parallel()
	defer func() { _ = recover() }()
	NewUnary[*string, *string]("test", func(_ *string) authz.Resource { return authz.ThisNode() }, nil)
	t.Error("expected panic")
}

func TestNewServerStream_PanicsWithoutAction(t *testing.T) {
	t.Parallel()
	defer func() { _ = recover() }()
	NewServerStream("", func(_ *string) authz.Resource { return authz.ThisNode() }, func(_ context.Context, _ *string, _ func(*string) error) error { return nil })
	t.Error("expected panic")
}

func TestNewServerStream_PanicsWithoutResource(t *testing.T) {
	t.Parallel()
	defer func() { _ = recover() }()
	NewServerStream[*string, *string]("test", nil, func(_ context.Context, _ *string, _ func(*string) error) error { return nil })
	t.Error("expected panic")
}

func TestNewServerStream_PanicsWithoutFn(t *testing.T) {
	t.Parallel()
	defer func() { _ = recover() }()
	NewServerStream[*string, *string]("test", func(_ *string) authz.Resource { return authz.ThisNode() }, nil)
	t.Error("expected panic")
}

// --- Execute tests (the critical auth path) ---

func TestExecute_NoIdentity_Rejected(t *testing.T) {
	t.Parallel()

	h := NewReadOnly("core:GetTest", func(_ context.Context, req *string) (*string, error) {
		t.Error("handler should not be called without identity")
		return nil, nil
	})

	_, err := h.Execute(context.Background(), Deps{}, strPtr("req"))
	if err == nil {
		t.Fatal("expected error for missing identity")
	}
}

func TestExecute_WithIdentity_NilAuthz_Denied(t *testing.T) {
	t.Parallel()

	h := NewReadOnly("core:GetTest", func(_ context.Context, req *string) (*string, error) {
		t.Error("handler should not be called with nil authorizer")
		return nil, nil
	})

	_, err := h.Execute(authnCtx("admin"), Deps{}, strPtr("req"))
	if err == nil {
		t.Fatal("expected error — nil authorizer should deny")
	}
}

func TestExecute_AuthzAllow(t *testing.T) {
	t.Parallel()

	az := &fakeAuthorizer{decision: authz.Allow}
	h := NewUnary("lifecycle:StageUpgrade",
		func(req *string) authz.Resource { return authz.ImageResource(*req) },
		func(_ context.Context, req *string) (*string, error) { return strPtr("done"), nil },
	)

	resp, err := h.Execute(authnCtx("admin"), Deps{Authz: az}, strPtr("registry.example.com/os:v2"))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if *resp != "done" {
		t.Errorf("resp = %q", *resp)
	}
	if az.lastAction != "lifecycle:StageUpgrade" {
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
	h := NewUnary("lifecycle:StartReboot",
		func(_ *string) authz.Resource { return authz.NodeResource("*") },
		func(_ context.Context, _ *string) (*string, error) {
			t.Error("handler should not be called when denied")
			return nil, nil
		},
	)

	_, err := h.Execute(authnCtx("readonly-user"), Deps{Authz: az}, strPtr(""))
	if err == nil {
		t.Fatal("expected error for denied access")
	}
}

func TestExecute_AuthzError(t *testing.T) {
	t.Parallel()

	az := &fakeAuthorizer{err: fmt.Errorf("policy engine error")}
	h := NewReadOnly("diagnostics:GetStats", func(_ context.Context, _ *string) (*string, error) {
		t.Error("handler should not be called on authz error")
		return nil, nil
	})

	_, err := h.Execute(authnCtx("admin"), Deps{Authz: az}, strPtr(""))
	if err == nil {
		t.Fatal("expected error for authz failure")
	}
}

func TestExecute_ResourcePassedToAuthz(t *testing.T) {
	t.Parallel()

	az := &fakeAuthorizer{decision: authz.Allow}
	h := NewUnary("services:StartService",
		func(req *string) authz.Resource { return authz.ServiceResource(*req) },
		func(_ context.Context, _ *string) (*string, error) { return strPtr("ok"), nil },
	)

	_, _ = h.Execute(authnCtx("admin"), Deps{Authz: az}, strPtr("crio.service"))

	if az.lastResource.Type != authz.ResourceService {
		t.Errorf("resource type = %q, want Service", az.lastResource.Type)
	}
	if az.lastResource.ID != "crio.service" {
		t.Errorf("resource ID = %q", az.lastResource.ID)
	}
}

func TestExecute_InvalidResource_Rejected(t *testing.T) {
	t.Parallel()

	h := NewUnary("core:GetBad",
		func(_ *string) authz.Resource { return authz.Resource{} },
		func(_ context.Context, _ *string) (*string, error) {
			t.Error("handler should not be called with invalid resource")
			return nil, nil
		},
	)

	_, err := h.Execute(authnCtx("admin"), Deps{}, strPtr(""))
	if err == nil {
		t.Fatal("expected error for invalid resource")
	}
}

// --- ServerStream Execute tests ---

func TestStreamExecute_NoIdentity_Rejected(t *testing.T) {
	t.Parallel()

	h := NewReadOnlyStream("diagnostics:StreamLogs", func(_ context.Context, _ *string, _ func(*string) error) error {
		t.Error("should not be called")
		return nil
	})

	err := h.Execute(context.Background(), Deps{}, strPtr(""), func(_ *string) error { return nil })
	if err == nil {
		t.Fatal("expected error for missing identity")
	}
}

func TestStreamExecute_AuthzDeny(t *testing.T) {
	t.Parallel()

	az := &fakeAuthorizer{decision: authz.Deny}
	h := NewReadOnlyStream("diagnostics:StreamLogs", func(_ context.Context, _ *string, _ func(*string) error) error {
		t.Error("should not be called when denied")
		return nil
	})

	err := h.Execute(authnCtx("user"), Deps{Authz: az}, strPtr(""), func(_ *string) error { return nil })
	if err == nil {
		t.Fatal("expected error for denied")
	}
}

func TestStreamExecute_AuthzAllow(t *testing.T) {
	t.Parallel()

	az := &fakeAuthorizer{decision: authz.Allow}
	called := false
	h := NewReadOnlyStream("diagnostics:StreamLogs", func(_ context.Context, _ *string, send func(*string) error) error {
		called = true
		return send(strPtr("log line"))
	})

	var received string
	err := h.Execute(authnCtx("admin"), Deps{Authz: az}, strPtr(""), func(s *string) error {
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
	h := NewReadOnly("core:GetVersion", func(_ context.Context, _ *string) (*string, error) {
		return strPtr("ok"), nil
	})

	_, _ = h.Execute(authnCtx("user"), Deps{Authz: az}, strPtr(""))

	if az.lastResource.Type != authz.ResourceNode || az.lastResource.ID != "*" {
		t.Errorf("ReadOnly resource = %s, want Node::*", az.lastResource)
	}
}

// --- Audit integration tests ---

type fakeAuditLogger struct {
	events []audit.Event
}

func (f *fakeAuditLogger) Log(event audit.Event)       { f.events = append(f.events, event) }
func (f *fakeAuditLogger) ShouldLog(_, _, _, _ string) bool { return true }
func (f *fakeAuditLogger) Subscribe() <-chan audit.Event     { return nil }
func (f *fakeAuditLogger) Close() error                     { return nil }

type excludingAuditLogger struct {
	fakeAuditLogger
	excludeIdentity string
	excludeAction   string
}

func (f *excludingAuditLogger) ShouldLog(identity, action, _, outcome string) bool {
	if outcome != "success" {
		return true
	}
	return identity != f.excludeIdentity || (f.excludeAction != "" && action != f.excludeAction)
}

func TestExecute_AuditEmitted_OnSuccess(t *testing.T) {
	t.Parallel()

	az := &fakeAuthorizer{decision: authz.Allow}
	al := &fakeAuditLogger{}
	h := NewUnary("lifecycle:StageUpgrade",
		func(req *string) authz.Resource { return authz.ImageResource(*req) },
		func(_ context.Context, _ *string) (*string, error) { return strPtr("ok"), nil },
	)

	_, _ = h.Execute(authnCtx("admin"), Deps{Authz: az, Audit: al}, strPtr("registry/os:v2"))

	if len(al.events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(al.events))
	}
	ev := al.events[0]
	if ev.Outcome != "success" {
		t.Errorf("Outcome = %q", ev.Outcome)
	}
	if ev.Identity != "admin" {
		t.Errorf("Identity = %q", ev.Identity)
	}
	if ev.Action != "lifecycle:StageUpgrade" {
		t.Errorf("Action = %q", ev.Action)
	}
	if ev.ResourceType != "Image" {
		t.Errorf("ResourceType = %q", ev.ResourceType)
	}
	if ev.ResourceID != "registry/os:v2" {
		t.Errorf("ResourceID = %q", ev.ResourceID)
	}
}

func TestExecute_AuditEmitted_OnDeny(t *testing.T) {
	t.Parallel()

	az := &fakeAuthorizer{decision: authz.Deny}
	al := &fakeAuditLogger{}
	h := NewUnary("lifecycle:StartReboot",
		func(_ *string) authz.Resource { return authz.NodeResource("*") },
		func(_ context.Context, _ *string) (*string, error) { return nil, nil },
	)

	_, _ = h.Execute(authnCtx("attacker"), Deps{Authz: az, Audit: al}, strPtr(""))

	if len(al.events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(al.events))
	}
	if al.events[0].Outcome != "denied" {
		t.Errorf("Outcome = %q, want denied", al.events[0].Outcome)
	}
}

func TestExecute_AuditEmitted_OnUnauthenticated(t *testing.T) {
	t.Parallel()

	al := &fakeAuditLogger{}
	h := NewReadOnly("core:GetVersion", func(_ context.Context, _ *string) (*string, error) { return nil, nil })

	_, _ = h.Execute(context.Background(), Deps{Audit: al}, strPtr(""))

	if len(al.events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(al.events))
	}
	if al.events[0].Outcome != "unauthenticated" {
		t.Errorf("Outcome = %q", al.events[0].Outcome)
	}
}

func TestExecute_AuditEmitted_OnHandlerError(t *testing.T) {
	t.Parallel()

	az := &fakeAuthorizer{decision: authz.Allow}
	al := &fakeAuditLogger{}
	h := NewReadOnly("diagnostics:GetStats", func(_ context.Context, _ *string) (*string, error) {
		return nil, fmt.Errorf("disk error")
	})

	_, _ = h.Execute(authnCtx("admin"), Deps{Authz: az, Audit: al}, strPtr(""))

	if len(al.events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(al.events))
	}
	if al.events[0].Outcome != "error" {
		t.Errorf("Outcome = %q, want error", al.events[0].Outcome)
	}
}

func TestExecute_AuditNotEmitted_WhenExcluded(t *testing.T) {
	t.Parallel()

	az := &fakeAuthorizer{decision: authz.Allow}
	al := &excludingAuditLogger{excludeIdentity: "prometheus", excludeAction: "core:GetHealth"}
	h := NewReadOnly("core:GetHealth", func(_ context.Context, _ *string) (*string, error) { return strPtr("ok"), nil })

	_, _ = h.Execute(authnCtx("prometheus"), Deps{Authz: az, Audit: al}, strPtr(""))

	if len(al.events) != 0 {
		t.Errorf("expected 0 audit events for excluded identity+action, got %d", len(al.events))
	}
}

func TestExecute_AuditEmitted_ExcludedIdentityDenied(t *testing.T) {
	t.Parallel()

	az := &fakeAuthorizer{decision: authz.Deny}
	al := &excludingAuditLogger{excludeIdentity: "prometheus", excludeAction: "lifecycle:StartReboot"}
	h := NewUnary("lifecycle:StartReboot",
		func(_ *string) authz.Resource { return authz.NodeResource("*") },
		func(_ context.Context, _ *string) (*string, error) { return nil, nil },
	)

	_, _ = h.Execute(authnCtx("prometheus"), Deps{Authz: az, Audit: al}, strPtr(""))

	if len(al.events) != 1 {
		t.Fatalf("denied should always be audited even for excluded identity, got %d", len(al.events))
	}
	if al.events[0].Outcome != "denied" {
		t.Errorf("Outcome = %q", al.events[0].Outcome)
	}
}

func TestExecute_NoAudit_WhenNil(t *testing.T) {
	t.Parallel()

	az := &fakeAuthorizer{decision: authz.Allow}
	h := NewReadOnly("core:GetVersion", func(_ context.Context, _ *string) (*string, error) { return strPtr("ok"), nil })

	// Should not panic with nil audit logger
	_, err := h.Execute(authnCtx("admin"), Deps{Authz: az}, strPtr(""))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
}

func TestStreamExecute_AuditEmitted(t *testing.T) {
	t.Parallel()

	az := &fakeAuthorizer{decision: authz.Allow}
	al := &fakeAuditLogger{}
	h := NewReadOnlyStream("diagnostics:StreamLogs", func(_ context.Context, _ *string, send func(*string) error) error {
		return send(strPtr("line"))
	})

	_ = h.Execute(authnCtx("admin"), Deps{Authz: az, Audit: al}, strPtr(""), func(_ *string) error { return nil })

	if len(al.events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(al.events))
	}
	if al.events[0].Action != "diagnostics:StreamLogs" {
		t.Errorf("Action = %q", al.events[0].Action)
	}
}

func strPtr(s string) *string { return &s }
