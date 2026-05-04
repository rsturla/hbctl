package authz

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"

	"github.com/rsturla/hbctl/internal/authn"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Decision int

const (
	Deny  Decision = 0
	Allow Decision = 1
)

type Authorizer interface {
	Name() string
	Authorize(ctx context.Context, identity authn.Identity, action string, resource Resource) (Decision, error)
}

type Factory func(cfg json.RawMessage) (Authorizer, error)

type Registry struct {
	mu        sync.RWMutex
	factories map[string]Factory
}

func NewRegistry() *Registry {
	return &Registry{factories: make(map[string]Factory)}
}

func (r *Registry) Register(name string, factory Factory) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.factories[name]; ok {
		return fmt.Errorf("authorizer already registered: %q", name)
	}
	r.factories[name] = factory
	return nil
}

func (r *Registry) Create(name string, cfg json.RawMessage) (Authorizer, error) {
	r.mu.RLock()
	factory, ok := r.factories[name]
	r.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("unknown authorizer: %q (registered: %v)", name, r.Names())
	}
	return factory(cfg)
}

func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.factories))
	for name := range r.factories {
		names = append(names, name)
	}
	return names
}

func UnaryInterceptor(az Authorizer, resources *ResourceMap) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		id, ok := authn.IdentityFromContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "no identity in context")
		}

		resource := ThisNode()
		if resources != nil {
			resource = resources.Extract(info.FullMethod, req)
		}

		decision, err := az.Authorize(ctx, id, info.FullMethod, resource)
		if err != nil {
			slog.Warn("authorization error", "identity", id.Name, "action", info.FullMethod, "resource", resource, "error", err)
			return nil, status.Error(codes.Internal, "authorization error")
		}
		if decision != Allow {
			slog.Warn("authorization denied", "identity", id.Name, "action", info.FullMethod, "resource", resource)
			return nil, status.Errorf(codes.PermissionDenied, "access denied")
		}

		ac := NewContext(az, id, info.FullMethod)
		return handler(ContextWith(ctx, ac), req)
	}
}

func StreamInterceptor(az Authorizer) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		id, ok := authn.IdentityFromContext(ss.Context())
		if !ok {
			return status.Error(codes.Unauthenticated, "no identity in context")
		}

		decision, err := az.Authorize(ss.Context(), id, info.FullMethod, ThisNode())
		if err != nil {
			slog.Warn("authorization error", "identity", id.Name, "action", info.FullMethod, "error", err)
			return status.Error(codes.Internal, "authorization error")
		}
		if decision != Allow {
			slog.Warn("authorization denied", "identity", id.Name, "action", info.FullMethod)
			return status.Errorf(codes.PermissionDenied, "access denied")
		}

		ac := NewContext(az, id, info.FullMethod)
		return handler(srv, &wrappedStream{ServerStream: ss, ctx: ContextWith(ss.Context(), ac)})
	}
}

type wrappedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *wrappedStream) Context() context.Context {
	return s.ctx
}

type AllowAll struct{}

func NewAllowAll(_ json.RawMessage) (Authorizer, error) { return &AllowAll{}, nil }
func (a *AllowAll) Name() string                          { return "allow-all" }
func (a *AllowAll) Authorize(_ context.Context, _ authn.Identity, _ string, _ Resource) (Decision, error) {
	return Allow, nil
}
