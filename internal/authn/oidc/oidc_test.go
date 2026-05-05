package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"google.golang.org/grpc/metadata"
)

type mockOIDC struct {
	key    *ecdsa.PrivateKey
	kid    string
	issuer string
}

func newMockOIDC(t *testing.T) (*mockOIDC, *httptest.Server) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	m := &mockOIDC{key: key, kid: "test-key-1"}

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	m.issuer = srv.URL

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"issuer":"%s","jwks_uri":"%s/jwks"}`, m.issuer, m.issuer)
	})

	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		xBytes := key.X.Bytes()
		yBytes := key.Y.Bytes()
		_, _ = fmt.Fprintf(w, `{"keys":[{"kty":"EC","kid":"%s","crv":"P-256","x":"%s","y":"%s"}]}`,
			m.kid,
			base64.RawURLEncoding.EncodeToString(xBytes),
			base64.RawURLEncoding.EncodeToString(yBytes),
		)
	})

	return m, srv
}

func (m *mockOIDC) signToken(claims map[string]any) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(
		fmt.Sprintf(`{"alg":"ES256","kid":"%s","typ":"JWT"}`, m.kid),
	))

	claimsJSON, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)

	signed := []byte(header + "." + payload)
	h := sha256.Sum256(signed)
	sig, _ := ecdsa.SignASN1(rand.Reader, m.key, h[:])

	return header + "." + payload + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func (m *mockOIDC) validClaims() map[string]any {
	return map[string]any{
		"iss":    m.issuer,
		"aud":    "hb-agent",
		"sub":    "user@example.com",
		"exp":    float64(time.Now().Add(time.Hour).Unix()),
		"iat":    float64(time.Now().Unix()),
		"groups": []any{"admins", "sre"},
	}
}

func newTestProvider(t *testing.T, m *mockOIDC) *Provider {
	t.Helper()
	cfg, _ := json.Marshal(Config{
		Issuer:   m.issuer,
		Audience: "hb-agent",
	})
	auth, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return auth.(*Provider)
}

func TestAuthenticate_ValidToken(t *testing.T) {
	m, srv := newMockOIDC(t)
	defer srv.Close()

	p := newTestProvider(t, m)
	token := m.signToken(m.validClaims())

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"authorization", "Bearer "+token,
	))

	id, err := p.Authenticate(ctx)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if id.Name != "user@example.com" {
		t.Errorf("Name = %q", id.Name)
	}
	if len(id.Groups) != 2 || id.Groups[0] != "admins" {
		t.Errorf("Groups = %v", id.Groups)
	}
	if id.Meta["provider"] != "oidc" {
		t.Errorf("Meta[provider] = %q", id.Meta["provider"])
	}
}

func TestAuthenticate_ExpiredToken(t *testing.T) {
	m, srv := newMockOIDC(t)
	defer srv.Close()

	p := newTestProvider(t, m)

	claims := m.validClaims()
	claims["exp"] = float64(time.Now().Add(-time.Hour).Unix())
	token := m.signToken(claims)

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"authorization", "Bearer "+token,
	))

	_, err := p.Authenticate(ctx)
	if err == nil {
		t.Error("expected error for expired token")
	}
}

func TestAuthenticate_WrongIssuer(t *testing.T) {
	m, srv := newMockOIDC(t)
	defer srv.Close()

	p := newTestProvider(t, m)

	claims := m.validClaims()
	claims["iss"] = "https://evil.com"
	token := m.signToken(claims)

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"authorization", "Bearer "+token,
	))

	_, err := p.Authenticate(ctx)
	if err == nil {
		t.Error("expected error for wrong issuer")
	}
}

func TestAuthenticate_WrongAudience(t *testing.T) {
	m, srv := newMockOIDC(t)
	defer srv.Close()

	p := newTestProvider(t, m)

	claims := m.validClaims()
	claims["aud"] = "other-service"
	token := m.signToken(claims)

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"authorization", "Bearer "+token,
	))

	_, err := p.Authenticate(ctx)
	if err == nil {
		t.Error("expected error for wrong audience")
	}
}

func TestAuthenticate_InvalidSignature(t *testing.T) {
	m, srv := newMockOIDC(t)
	defer srv.Close()

	p := newTestProvider(t, m)
	token := m.signToken(m.validClaims())

	// Tamper with the payload
	parts := splitToken(token)
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"evil","iss":"` + m.issuer + `","aud":"hb-agent","exp":` + fmt.Sprintf("%d", time.Now().Add(time.Hour).Unix()) + `}`))
	tampered := parts[0] + "." + parts[1] + "." + parts[2]

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"authorization", "Bearer "+tampered,
	))

	_, err := p.Authenticate(ctx)
	if err == nil {
		t.Error("expected error for tampered token")
	}
}

func TestAuthenticate_NoAuthHeader(t *testing.T) {
	m, srv := newMockOIDC(t)
	defer srv.Close()

	p := newTestProvider(t, m)

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs())
	_, err := p.Authenticate(ctx)
	if err == nil {
		t.Error("expected error for missing auth header")
	}
}

func TestAuthenticate_WrongScheme(t *testing.T) {
	m, srv := newMockOIDC(t)
	defer srv.Close()

	p := newTestProvider(t, m)

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"authorization", "Basic dXNlcjpwYXNz",
	))

	_, err := p.Authenticate(ctx)
	if err == nil {
		t.Error("expected error for non-Bearer scheme")
	}
}

func TestAuthenticate_MissingSub(t *testing.T) {
	m, srv := newMockOIDC(t)
	defer srv.Close()

	p := newTestProvider(t, m)

	claims := m.validClaims()
	delete(claims, "sub")
	token := m.signToken(claims)

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"authorization", "Bearer "+token,
	))

	_, err := p.Authenticate(ctx)
	if err == nil {
		t.Error("expected error for missing sub")
	}
}

func TestAuthenticate_AudienceArray(t *testing.T) {
	m, srv := newMockOIDC(t)
	defer srv.Close()

	p := newTestProvider(t, m)

	claims := m.validClaims()
	claims["aud"] = []any{"other-service", "hb-agent"}
	token := m.signToken(claims)

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"authorization", "Bearer "+token,
	))

	id, err := p.Authenticate(ctx)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if id.Name != "user@example.com" {
		t.Errorf("Name = %q", id.Name)
	}
}

func TestAuthenticate_CustomClaims(t *testing.T) {
	m, srv := newMockOIDC(t)
	defer srv.Close()

	cfg, _ := json.Marshal(Config{
		Issuer:        m.issuer,
		Audience:      "hb-agent",
		UsernameClaim: "email",
		GroupsClaim:   "roles",
	})
	auth, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	p := auth.(*Provider)

	claims := m.validClaims()
	claims["email"] = "admin@corp.com"
	claims["roles"] = []any{"cluster-admin"}
	token := m.signToken(claims)

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"authorization", "Bearer "+token,
	))

	id, err := p.Authenticate(ctx)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if id.Name != "admin@corp.com" {
		t.Errorf("Name = %q", id.Name)
	}
	if len(id.Groups) != 1 || id.Groups[0] != "cluster-admin" {
		t.Errorf("Groups = %v", id.Groups)
	}
}

func TestNew_MissingIssuer(t *testing.T) {
	cfg, _ := json.Marshal(Config{Audience: "test"})
	_, err := New(cfg)
	if err == nil {
		t.Error("expected error for missing issuer")
	}
}

func TestNew_MissingAudience(t *testing.T) {
	_, srv := newMockOIDC(t)
	defer srv.Close()
	cfg, _ := json.Marshal(Config{Issuer: srv.URL})
	_, err := New(cfg)
	if err == nil {
		t.Error("expected error for missing audience")
	}
}

func TestNew_NilConfig(t *testing.T) {
	_, err := New(nil)
	if err == nil {
		t.Error("expected error for nil config")
	}
}

func TestName(t *testing.T) {
	m, srv := newMockOIDC(t)
	defer srv.Close()
	p := newTestProvider(t, m)
	if p.Name() != "oidc" {
		t.Errorf("Name = %q", p.Name())
	}
}

func TestVerifyAudience_String(t *testing.T) {
	err := verifyAudience(map[string]any{"aud": "hb-agent"}, "hb-agent")
	if err != nil {
		t.Errorf("verifyAudience: %v", err)
	}
}

func TestVerifyAudience_StringMismatch(t *testing.T) {
	err := verifyAudience(map[string]any{"aud": "other"}, "hb-agent")
	if err == nil {
		t.Error("expected error for audience mismatch")
	}
}

func TestVerifyAudience_Array(t *testing.T) {
	err := verifyAudience(map[string]any{"aud": []any{"a", "hb-agent", "b"}}, "hb-agent")
	if err != nil {
		t.Errorf("verifyAudience: %v", err)
	}
}

func TestVerifyAudience_Missing(t *testing.T) {
	err := verifyAudience(map[string]any{}, "hb-agent")
	if err == nil {
		t.Error("expected error for missing audience")
	}
}

func TestJWKParsing_RSA(t *testing.T) {
	k := jwk{
		Kty: "RSA",
		N:   base64.RawURLEncoding.EncodeToString(big.NewInt(12345).Bytes()),
		E:   base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}),
	}
	pub, err := k.toPublicKey()
	if err != nil {
		t.Fatalf("toPublicKey: %v", err)
	}
	if _, ok := pub.(*big.Int); ok {
		t.Error("should be *rsa.PublicKey")
	}
}

func TestJWKParsing_EC(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	k := jwk{
		Kty: "EC",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(key.X.Bytes()),
		Y:   base64.RawURLEncoding.EncodeToString(key.Y.Bytes()),
	}
	pub, err := k.toPublicKey()
	if err != nil {
		t.Fatalf("toPublicKey: %v", err)
	}
	ecKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("expected *ecdsa.PublicKey")
	}
	if ecKey.Curve != elliptic.P256() {
		t.Error("wrong curve")
	}
}

func TestJWKParsing_UnsupportedType(t *testing.T) {
	k := jwk{Kty: "OKP"}
	_, err := k.toPublicKey()
	if err == nil {
		t.Error("expected error for unsupported key type")
	}
}

func splitToken(token string) [3]string {
	parts := [3]string{}
	for i, p := range splitString(token, ".") {
		if i < 3 {
			parts[i] = p
		}
	}
	return parts
}

func splitString(s, sep string) []string {
	result := []string{}
	for len(s) > 0 {
		idx := indexOf(s, sep)
		if idx < 0 {
			result = append(result, s)
			break
		}
		result = append(result, s[:idx])
		s = s[idx+len(sep):]
	}
	return result
}

func indexOf(s, sub string) int {
	for i := range s {
		if i+len(sub) <= len(s) && s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
