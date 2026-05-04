package authz

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/rsturla/hbctl/internal/authn"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type authzContextKey struct{}
type resourceCheckedKey struct{}

type Context struct {
	az       Authorizer
	identity authn.Identity
	action   string
}

func NewContext(az Authorizer, identity authn.Identity, action string) *Context {
	return &Context{az: az, identity: identity, action: action}
}

func ContextFrom(ctx context.Context) (*Context, bool) {
	ac, ok := ctx.Value(authzContextKey{}).(*Context)
	return ac, ok
}

func ContextWith(ctx context.Context, ac *Context) context.Context {
	return context.WithValue(ctx, authzContextKey{}, ac)
}

func (c *Context) Identity() authn.Identity {
	return c.identity
}

func ResourceChecked(ctx context.Context) bool {
	v, _ := ctx.Value(resourceCheckedKey{}).(bool)
	return v
}

func (c *Context) CheckAccess(ctx context.Context, resource Resource) error {
	if err := resource.Validate(); err != nil {
		return status.Errorf(codes.InvalidArgument, "invalid resource: %v", err)
	}
	if c.az == nil {
		return nil
	}
	d, err := c.az.Authorize(ctx, c.identity, c.action, resource)
	if err != nil {
		slog.Warn("authorization error",
			"identity", c.identity.Name,
			"action", c.action,
			"resource", resource,
			"error", err,
		)
		return status.Error(codes.Internal, "authorization error")
	}
	if d != Allow {
		slog.Warn("authorization denied",
			"identity", c.identity.Name,
			"action", c.action,
			"resource", resource,
		)
		return status.Errorf(codes.PermissionDenied, "access denied to %s", resource)
	}
	slog.Debug("authorized",
		"identity", c.identity.Name,
		"action", c.action,
		"resource", resource,
	)
	return nil
}

func MustCheckAccess(ctx context.Context, resource Resource) error {
	ac, ok := ContextFrom(ctx)
	if !ok {
		return fmt.Errorf("no authorization context")
	}
	return ac.CheckAccess(ctx, resource)
}

func MarkResourceChecked(ctx context.Context) context.Context {
	return context.WithValue(ctx, resourceCheckedKey{}, true)
}
