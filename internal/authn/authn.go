package authn

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Identity struct {
	Name   string
	Groups []string
	Meta   map[string]string
}

type Authenticator interface {
	Name() string
	Authenticate(ctx context.Context) (Identity, error)
}

type Factory func(cfg json.RawMessage) (Authenticator, error)

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
		return fmt.Errorf("authenticator already registered: %q", name)
	}
	r.factories[name] = factory
	return nil
}

func (r *Registry) Create(name string, cfg json.RawMessage) (Authenticator, error) {
	r.mu.RLock()
	factory, ok := r.factories[name]
	r.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("unknown authenticator: %q (registered: %v)", name, r.Names())
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

type contextKey struct{}

func IdentityFromContext(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(contextKey{}).(Identity)
	return id, ok
}

func ContextWithIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, contextKey{}, id)
}

func UnaryInterceptor(auth Authenticator, skipMethods map[string]bool) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if skipMethods[info.FullMethod] {
			return handler(ctx, req)
		}
		id, err := auth.Authenticate(ctx)
		if err != nil {
			return nil, status.Errorf(codes.Unauthenticated, "authentication failed: %v", err)
		}
		return handler(ContextWithIdentity(ctx, id), req)
	}
}

func StreamInterceptor(auth Authenticator, skipMethods map[string]bool) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if skipMethods[info.FullMethod] {
			return handler(srv, ss)
		}
		id, err := auth.Authenticate(ss.Context())
		if err != nil {
			return status.Errorf(codes.Unauthenticated, "authentication failed: %v", err)
		}
		return handler(srv, &authenticatedStream{ServerStream: ss, ctx: ContextWithIdentity(ss.Context(), id)})
	}
}

type authenticatedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *authenticatedStream) Context() context.Context {
	return s.ctx
}
