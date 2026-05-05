package handler

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"

	"github.com/rsturla/hbctl/internal/audit"
	"github.com/rsturla/hbctl/internal/authn"
	"github.com/rsturla/hbctl/internal/authz"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// Verb is the allowed set of action verbs.
// Actions must be formatted as <plugin>:<Verb><Noun>.
type Verb string

const (
	VerbGet      Verb = "Get"      // Read single resource
	VerbDescribe Verb = "Describe" // Read detailed resource info
	VerbList     Verb = "List"     // Read multiple resources
	VerbStream   Verb = "Stream"   // Server-streaming read
	VerbPut      Verb = "Put"      // Create or replace
	VerbStart    Verb = "Start"    // Start a resource
	VerbStop     Verb = "Stop"     // Stop a resource
	VerbRestart  Verb = "Restart"  // Restart a resource
	VerbStage    Verb = "Stage"    // Prepare but don't activate
	VerbRollback Verb = "Rollback" // Revert to previous state
	
	VerbBootstrap Verb = "Bootstrap" // Initial credential setup
)

var allowedVerbs = map[Verb]bool{
	VerbGet: true, VerbDescribe: true, VerbList: true, VerbStream: true,
	VerbPut: true, VerbStart: true, VerbStop: true, VerbRestart: true,
	VerbStage: true, VerbRollback: true, VerbBootstrap: true,
}

var actionRe = regexp.MustCompile(`^([a-z]+):([A-Z][a-z]+)([A-Z][a-zA-Z]*)$`)

func validateAction(action string) {
	matches := actionRe.FindStringSubmatch(action)
	if matches == nil {
		panic(fmt.Sprintf("handler: action %q must match <plugin>:<Verb><Noun> (e.g., services:StartService)", action))
	}
	verb := Verb(matches[2])
	if !allowedVerbs[verb] {
		panic(fmt.Sprintf("handler: unknown verb %q in action %q (allowed: Get, Describe, List, Stream, Put, Start, Stop, Restart, Stage, Rollback, Bootstrap)", verb, action))
	}
}

// Action constructs a validated action string.
func Action(plugin string, verb Verb, noun string) string {
	action := fmt.Sprintf("%s:%s%s", plugin, verb, noun)
	validateAction(action)
	return action
}

type Deps struct {
	Authz authz.Authorizer
	Audit audit.Logger
}

type Unary[Req, Resp any] struct {
	action   string
	resource func(Req) authz.Resource
	fn       func(context.Context, Req) (Resp, error)
}

func NewUnary[Req, Resp any](
	action string,
	resource func(Req) authz.Resource,
	fn func(context.Context, Req) (Resp, error),
) Unary[Req, Resp] {
	validateAction(action)
	if resource == nil {
		panic("handler: resource extractor required")
	}
	if fn == nil {
		panic("handler: function required")
	}
	return Unary[Req, Resp]{action: action, resource: resource, fn: fn}
}

func NewReadOnly[Req, Resp any](
	action string,
	fn func(context.Context, Req) (Resp, error),
) Unary[Req, Resp] {
	return NewUnary(action, func(_ Req) authz.Resource { return authz.ThisNode() }, fn)
}

func (h Unary[Req, Resp]) Execute(ctx context.Context, deps Deps, req Req) (Resp, error) {
	var zero Resp
	addr := peerAddr(ctx)

	id, ok := authn.IdentityFromContext(ctx)
	if !ok {
		emitAudit(deps.Audit, "", h.action, authz.ThisNode(), "unauthenticated", addr)
		return zero, status.Error(codes.Unauthenticated, "no identity in context")
	}

	resource := h.resource(req)
	if err := resource.Validate(); err != nil {
		return zero, status.Errorf(codes.InvalidArgument, "invalid resource: %v", err)
	}

	if deps.Authz == nil {
		slog.Error("no authorizer configured", "identity", id.Name, "action", h.action)
		emitAudit(deps.Audit, id.Name, h.action, resource, "denied", addr)
		return zero, status.Error(codes.PermissionDenied, "no authorizer configured")
	}

	decision, err := deps.Authz.Authorize(ctx, id, h.action, resource)
	if err != nil {
		slog.Warn("authorization error", "identity", id.Name, "action", h.action, "error", err)
		emitAudit(deps.Audit, id.Name, h.action, resource, "error", addr)
		return zero, status.Error(codes.Internal, "authorization error")
	}
	if decision != authz.Allow {
		emitAudit(deps.Audit, id.Name, h.action, resource, "denied", addr)
		return zero, status.Errorf(codes.PermissionDenied, "access denied")
	}

	resp, fnErr := h.fn(ctx, req)

	outcome := "success"
	if fnErr != nil {
		outcome = "error"
	}
	emitAudit(deps.Audit, id.Name, h.action, resource, outcome, addr)

	return resp, fnErr
}

type ServerStream[Req, Resp any] struct {
	action   string
	resource func(Req) authz.Resource
	fn       func(context.Context, Req, func(Resp) error) error
}

func NewServerStream[Req, Resp any](
	action string,
	resource func(Req) authz.Resource,
	fn func(context.Context, Req, func(Resp) error) error,
) ServerStream[Req, Resp] {
	validateAction(action)
	if resource == nil {
		panic("handler: resource extractor required")
	}
	if fn == nil {
		panic("handler: function required")
	}
	return ServerStream[Req, Resp]{action: action, resource: resource, fn: fn}
}

func NewReadOnlyStream[Req, Resp any](
	action string,
	fn func(context.Context, Req, func(Resp) error) error,
) ServerStream[Req, Resp] {
	return NewServerStream(action, func(_ Req) authz.Resource { return authz.ThisNode() }, fn)
}

func (h ServerStream[Req, Resp]) Execute(ctx context.Context, deps Deps, req Req, send func(Resp) error) error {
	addr := peerAddr(ctx)

	id, ok := authn.IdentityFromContext(ctx)
	if !ok {
		emitAudit(deps.Audit, "", h.action, authz.ThisNode(), "unauthenticated", addr)
		return status.Error(codes.Unauthenticated, "no identity in context")
	}

	resource := h.resource(req)
	if err := resource.Validate(); err != nil {
		return status.Errorf(codes.InvalidArgument, "invalid resource: %v", err)
	}

	if deps.Authz == nil {
		emitAudit(deps.Audit, id.Name, h.action, resource, "denied", addr)
		return status.Error(codes.PermissionDenied, "no authorizer configured")
	}

	decision, err := deps.Authz.Authorize(ctx, id, h.action, resource)
	if err != nil {
		emitAudit(deps.Audit, id.Name, h.action, resource, "error", addr)
		return status.Error(codes.Internal, "authorization error")
	}
	if decision != authz.Allow {
		emitAudit(deps.Audit, id.Name, h.action, resource, "denied", addr)
		return status.Errorf(codes.PermissionDenied, "access denied")
	}

	fnErr := h.fn(ctx, req, send)

	outcome := "success"
	if fnErr != nil {
		outcome = "error"
	}
	emitAudit(deps.Audit, id.Name, h.action, resource, outcome, addr)

	return fnErr
}

func emitAudit(logger audit.Logger, identity, action string, resource authz.Resource, outcome, addr string) {
	if logger == nil {
		return
	}
	if !logger.ShouldLog(identity, action, resource.ID, outcome) {
		return
	}
	logger.Log(audit.Event{
		Type:         "rpc." + action,
		Identity:     identity,
		Action:       action,
		ResourceType: string(resource.Type),
		ResourceID:   resource.ID,
		Outcome:      outcome,
		PeerAddr:     addr,
	})
}

func peerAddr(ctx context.Context) string {
	if p, ok := peer.FromContext(ctx); ok {
		return p.Addr.String()
	}
	return ""
}
