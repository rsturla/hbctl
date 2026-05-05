package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/rsturla/hbctl/internal/authn"
	"google.golang.org/grpc/metadata"
)

type Config struct {
	Issuer        string `json:"issuer"`
	Audience      string `json:"audience"`
	GroupsClaim   string `json:"groups_claim"`
	UsernameClaim string `json:"username_claim"`
	CAFile        string `json:"ca_file"`
}

type Provider struct {
	cfg    Config
	jwks   *jwksCache
	client *http.Client
}

func New(raw json.RawMessage) (authn.Authenticator, error) {
	var cfg Config
	if raw == nil {
		return nil, fmt.Errorf("oidc config required")
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parse oidc config: %w", err)
	}
	if cfg.Issuer == "" {
		return nil, fmt.Errorf("oidc issuer required")
	}
	if cfg.Audience == "" {
		return nil, fmt.Errorf("oidc audience required")
	}
	if cfg.GroupsClaim == "" {
		cfg.GroupsClaim = "groups"
	}
	if cfg.UsernameClaim == "" {
		cfg.UsernameClaim = "sub"
	}

	client := &http.Client{Timeout: 10 * time.Second}

	if cfg.CAFile != "" {
		caPEM, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read OIDC CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("no valid certificates in %s", cfg.CAFile)
		}
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    pool,
				MinVersion: tls.VersionTLS12,
			},
		}
	}

	jwksURL, err := discoverJWKSURL(client, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("discover JWKS: %w", err)
	}

	return &Provider{
		cfg:    cfg,
		jwks:   newJWKSCache(client, jwksURL),
		client: client,
	}, nil
}

func (p *Provider) Name() string { return "oidc" }

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

	claims, err := p.verifyToken(token)
	if err != nil {
		return authn.Identity{}, fmt.Errorf("verify token: %w", err)
	}

	name, _ := claims[p.cfg.UsernameClaim].(string)
	if name == "" {
		return authn.Identity{}, fmt.Errorf("token missing %s claim", p.cfg.UsernameClaim)
	}

	var groups []string
	switch v := claims[p.cfg.GroupsClaim].(type) {
	case []any:
		for _, g := range v {
			if s, ok := g.(string); ok {
				groups = append(groups, s)
			}
		}
	case string:
		groups = strings.Split(v, ",")
	}

	issuer, _ := claims["iss"].(string)

	return authn.Identity{
		Name:   name,
		Groups: groups,
		Meta: map[string]string{
			"provider": "oidc",
			"issuer":   issuer,
		},
	}, nil
}

func (p *Provider) verifyToken(tokenStr string) (map[string]any, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}

	headerBytes, err := base64URLDecode(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decode header: %w", err)
	}

	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("parse header: %w", err)
	}

	key, err := p.jwks.getKey(header.Kid)
	if err != nil {
		return nil, fmt.Errorf("get signing key: %w", err)
	}

	sigBytes, err := base64URLDecode(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}

	signed := []byte(parts[0] + "." + parts[1])
	if err := verifySignature(header.Alg, key, signed, sigBytes); err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	payloadBytes, err := base64URLDecode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}

	var claims map[string]any
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("parse claims: %w", err)
	}

	if iss, _ := claims["iss"].(string); iss != p.cfg.Issuer {
		return nil, fmt.Errorf("issuer mismatch: got %q, want %q", iss, p.cfg.Issuer)
	}

	if err := verifyAudience(claims, p.cfg.Audience); err != nil {
		return nil, err
	}

	now := time.Now()

	if exp, ok := claims["exp"].(float64); ok {
		if time.Unix(int64(exp), 0).Before(now) {
			return nil, fmt.Errorf("token expired")
		}
	} else {
		return nil, fmt.Errorf("token missing exp claim")
	}

	if nbf, ok := claims["nbf"].(float64); ok {
		if time.Unix(int64(nbf), 0).After(now) {
			return nil, fmt.Errorf("token not yet valid")
		}
	}

	if iat, ok := claims["iat"].(float64); ok {
		maxAge := 24 * time.Hour
		if time.Since(time.Unix(int64(iat), 0)) > maxAge {
			return nil, fmt.Errorf("token too old (issued %v ago)", time.Since(time.Unix(int64(iat), 0)).Truncate(time.Minute))
		}
	}

	return claims, nil
}

func verifyAudience(claims map[string]any, expected string) error {
	switch v := claims["aud"].(type) {
	case string:
		if v != expected {
			return fmt.Errorf("audience mismatch: got %q, want %q", v, expected)
		}
	case []any:
		for _, a := range v {
			if s, ok := a.(string); ok && s == expected {
				return nil
			}
		}
		return fmt.Errorf("audience %q not found in token", expected)
	default:
		return fmt.Errorf("token missing aud claim")
	}
	return nil
}

func verifySignature(alg string, key crypto.PublicKey, signed, sig []byte) error {
	var hashFunc crypto.Hash
	switch alg {
	case "RS256", "ES256":
		hashFunc = crypto.SHA256
	case "RS384", "ES384":
		hashFunc = crypto.SHA384
	case "RS512", "ES512":
		hashFunc = crypto.SHA512
	default:
		return fmt.Errorf("unsupported algorithm: %s", alg)
	}

	h := hashFunc.New()
	h.Write(signed)
	digest := h.Sum(nil)

	switch k := key.(type) {
	case *rsa.PublicKey:
		if !strings.HasPrefix(alg, "RS") {
			return fmt.Errorf("algorithm %s incompatible with RSA key", alg)
		}
		if k.N.BitLen() < 2048 {
			return fmt.Errorf("RSA key too small: %d bits", k.N.BitLen())
		}
		return rsa.VerifyPKCS1v15(k, hashFunc, digest, sig)
	case *ecdsa.PublicKey:
		if !strings.HasPrefix(alg, "ES") {
			return fmt.Errorf("algorithm %s incompatible with ECDSA key", alg)
		}
		if !ecdsa.VerifyASN1(k, digest, sig) {
			return fmt.Errorf("ECDSA signature invalid")
		}
		return nil
	default:
		return fmt.Errorf("unsupported key type: %T", key)
	}
}

// --- JWKS cache ---

type jwksCache struct {
	mu          sync.RWMutex
	keys        map[string]crypto.PublicKey
	url         string
	client      *http.Client
	lastFetch   time.Time
	lastRefresh time.Time
	ttl         time.Duration
	cooldown    time.Duration
}

func newJWKSCache(client *http.Client, url string) *jwksCache {
	return &jwksCache{
		keys:     make(map[string]crypto.PublicKey),
		url:      url,
		client:   client,
		ttl:      1 * time.Hour,
		cooldown: 1 * time.Minute,
	}
}

func (c *jwksCache) getKey(kid string) (crypto.PublicKey, error) {
	c.mu.RLock()
	key, ok := c.keys[kid]
	stale := time.Since(c.lastFetch) > c.ttl
	c.mu.RUnlock()

	if ok && !stale {
		return key, nil
	}

	c.mu.RLock()
	coolingDown := time.Since(c.lastRefresh) < c.cooldown
	c.mu.RUnlock()

	if coolingDown {
		if ok {
			return key, nil
		}
		return nil, fmt.Errorf("key %q not found and JWKS refresh on cooldown", kid)
	}

	if err := c.refresh(); err != nil {
		if ok {
			slog.Warn("JWKS refresh failed, using cached key", "error", err)
			return key, nil
		}
		return nil, fmt.Errorf("JWKS fetch failed: %w", err)
	}

	c.mu.RLock()
	key, ok = c.keys[kid]
	c.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("key %q not found in JWKS", kid)
	}
	return key, nil
}

func (c *jwksCache) refresh() error {
	resp, err := c.client.Get(c.url)
	if err != nil {
		return fmt.Errorf("fetch JWKS: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read JWKS: %w", err)
	}

	var jwks struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(body, &jwks); err != nil {
		return fmt.Errorf("parse JWKS: %w", err)
	}

	keys := make(map[string]crypto.PublicKey, len(jwks.Keys))
	for _, k := range jwks.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		pub, err := k.toPublicKey()
		if err != nil {
			slog.Warn("skipping JWKS key", "kid", k.Kid, "error", err)
			continue
		}
		keys[k.Kid] = pub
	}

	now := time.Now()
	c.mu.Lock()
	c.keys = keys
	c.lastFetch = now
	c.lastRefresh = now
	c.mu.Unlock()

	slog.Debug("JWKS refreshed", "keys", len(keys))
	return nil
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func (k *jwk) toPublicKey() (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		return k.toRSAPublicKey()
	case "EC":
		return k.toECPublicKey()
	default:
		return nil, fmt.Errorf("unsupported key type: %s", k.Kty)
	}
}

func (k *jwk) toRSAPublicKey() (*rsa.PublicKey, error) {
	nBytes, err := base64URLDecode(k.N)
	if err != nil {
		return nil, fmt.Errorf("decode N: %w", err)
	}
	eBytes, err := base64URLDecode(k.E)
	if err != nil {
		return nil, fmt.Errorf("decode E: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := 0
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}

	return &rsa.PublicKey{N: n, E: e}, nil
}

func (k *jwk) toECPublicKey() (*ecdsa.PublicKey, error) {
	var curve elliptic.Curve
	switch k.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported curve: %s", k.Crv)
	}

	xBytes, err := base64URLDecode(k.X)
	if err != nil {
		return nil, fmt.Errorf("decode X: %w", err)
	}
	yBytes, err := base64URLDecode(k.Y)
	if err != nil {
		return nil, fmt.Errorf("decode Y: %w", err)
	}

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	pub := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}

	// Validate point is on curve via ecdh marshaling round-trip
	if _, err := pub.ECDH(); err != nil {
		return nil, fmt.Errorf("EC point not on curve %s: %w", k.Crv, err)
	}

	return pub, nil
}

// --- Discovery ---

func discoverJWKSURL(client *http.Client, issuer string) (string, error) {
	url := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"

	resp, err := client.Get(url)
	if err != nil {
		return "", fmt.Errorf("fetch OIDC discovery: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("OIDC discovery returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("read discovery: %w", err)
	}

	var disco struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.Unmarshal(body, &disco); err != nil {
		return "", fmt.Errorf("parse discovery: %w", err)
	}
	if disco.JWKSURI == "" {
		return "", fmt.Errorf("discovery missing jwks_uri")
	}

	if err := validateJWKSURL(issuer, disco.JWKSURI); err != nil {
		return "", err
	}

	return disco.JWKSURI, nil
}

func validateJWKSURL(issuer, jwksURI string) error {
	issuerHost := extractHost(issuer)
	jwksHost := extractHost(jwksURI)
	if issuerHost == "" || jwksHost == "" {
		return fmt.Errorf("cannot parse host from issuer or jwks_uri")
	}
	if issuerHost != jwksHost {
		return fmt.Errorf("jwks_uri host %q does not match issuer host %q", jwksHost, issuerHost)
	}
	return nil
}

func extractHost(rawURL string) string {
	// Simple extraction without net/url to avoid import
	s := rawURL
	if idx := strings.Index(s, "://"); idx >= 0 {
		s = s[idx+3:]
	}
	if idx := strings.Index(s, "/"); idx >= 0 {
		s = s[:idx]
	}
	if idx := strings.Index(s, ":"); idx >= 0 {
		s = s[:idx]
	}
	return s
}

func base64URLDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}
