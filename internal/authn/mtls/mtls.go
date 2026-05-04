package mtls

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/rsturla/hbctl/internal/authn"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

type Provider struct{}

func New(_ json.RawMessage) (authn.Authenticator, error) {
	return &Provider{}, nil
}

func (p *Provider) Name() string { return "mtls" }

func (p *Provider) Authenticate(ctx context.Context) (authn.Identity, error) {
	pr, ok := peer.FromContext(ctx)
	if !ok {
		return authn.Identity{}, fmt.Errorf("no peer in context")
	}

	tlsInfo, ok := pr.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return authn.Identity{}, fmt.Errorf("no TLS info in peer")
	}

	if len(tlsInfo.State.VerifiedChains) == 0 || len(tlsInfo.State.VerifiedChains[0]) == 0 {
		return authn.Identity{}, fmt.Errorf("no verified client certificate")
	}

	leaf := tlsInfo.State.VerifiedChains[0][0]

	return authn.Identity{
		Name:   leaf.Subject.CommonName,
		Groups: leaf.Subject.Organization,
		Meta: map[string]string{
			"provider":     "mtls",
			"serial":       leaf.SerialNumber.String(),
			"not_after":    leaf.NotAfter.String(),
		},
	}, nil
}
