package handler

import (
	"context"
	"log/slog"

	"github.com/rsturla/hbctl/internal/authn"
	"github.com/rsturla/hbctl/internal/authz"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

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
	if action == "" {
		panic("handler: action required")
	}
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

func (h Unary[Req, Resp]) Execute(ctx context.Context, az authz.Authorizer, req Req) (Resp, error) {
	var zero Resp

	id, ok := authn.IdentityFromContext(ctx)
	if !ok {
		return zero, status.Error(codes.Unauthenticated, "no identity in context")
	}

	resource := h.resource(req)
	if err := resource.Validate(); err != nil {
		return zero, status.Errorf(codes.InvalidArgument, "invalid resource: %v", err)
	}

	if az == nil {
		slog.Error("no authorizer configured, denying request",
			"identity", id.Name,
			"action", h.action,
			"resource", resource,
		)
		return zero, status.Error(codes.PermissionDenied, "no authorizer configured")
	}

	decision, err := az.Authorize(ctx, id, h.action, resource)
	if err != nil {
		slog.Warn("authorization error",
			"identity", id.Name,
			"action", h.action,
			"resource", resource,
			"error", err,
		)
		return zero, status.Error(codes.Internal, "authorization error")
	}
	if decision != authz.Allow {
		slog.Warn("authorization denied",
			"identity", id.Name,
			"action", h.action,
			"resource", resource,
		)
		return zero, status.Errorf(codes.PermissionDenied, "access denied")
	}

	slog.Debug("handling request",
		"identity", id.Name,
		"action", h.action,
		"resource", resource,
	)

	return h.fn(ctx, req)
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
	if action == "" {
		panic("handler: action required")
	}
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

func (h ServerStream[Req, Resp]) Execute(ctx context.Context, az authz.Authorizer, req Req, send func(Resp) error) error {
	id, ok := authn.IdentityFromContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "no identity in context")
	}

	resource := h.resource(req)
	if err := resource.Validate(); err != nil {
		return status.Errorf(codes.InvalidArgument, "invalid resource: %v", err)
	}

	if az == nil {
		return status.Error(codes.PermissionDenied, "no authorizer configured")
	}

	decision, err := az.Authorize(ctx, id, h.action, resource)
	if err != nil {
		return status.Error(codes.Internal, "authorization error")
	}
	if decision != authz.Allow {
		return status.Errorf(codes.PermissionDenied, "access denied")
	}

	return h.fn(ctx, req, send)
}
