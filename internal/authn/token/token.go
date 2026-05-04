package token

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/rsturla/hbctl/internal/authn"
	"google.golang.org/grpc/metadata"
)

type Config struct {
	TokenHash string `json:"token_hash"`
}

type Provider struct {
	hash []byte
}

func New(cfg json.RawMessage) (authn.Authenticator, error) {
	var c Config
	if cfg != nil {
		if err := json.Unmarshal(cfg, &c); err != nil {
			return nil, fmt.Errorf("parse token config: %w", err)
		}
	}

	if c.TokenHash == "" {
		return nil, fmt.Errorf("token_hash required")
	}

	hashStr := strings.TrimPrefix(c.TokenHash, "sha256:")
	hash, err := hex.DecodeString(hashStr)
	if err != nil {
		return nil, fmt.Errorf("decode token hash: %w", err)
	}

	return &Provider{hash: hash}, nil
}

func (p *Provider) Name() string { return "token" }

func (p *Provider) Authenticate(ctx context.Context) (authn.Identity, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return authn.Identity{}, fmt.Errorf("no metadata in context")
	}

	values := md.Get("authorization")
	if len(values) == 0 {
		return authn.Identity{}, fmt.Errorf("no authorization header")
	}

	token := strings.TrimPrefix(values[0], "Bearer ")
	token = strings.TrimPrefix(token, "bearer ")
	if token == values[0] {
		return authn.Identity{}, fmt.Errorf("authorization header must use Bearer scheme")
	}

	h := sha256.Sum256([]byte(token))
	defer clear(h[:])
	if subtle.ConstantTimeCompare(h[:], p.hash) != 1 {
		return authn.Identity{}, fmt.Errorf("invalid token")
	}

	return authn.Identity{
		Name: "bearer-token",
		Meta: map[string]string{"provider": "token"},
	}, nil
}

func HashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return "sha256:" + hex.EncodeToString(h[:])
}
