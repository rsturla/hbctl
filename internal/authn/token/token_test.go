package token

import (
	"context"
	"encoding/json"
	"testing"

	"google.golang.org/grpc/metadata"
)

func TestAuthenticate_ValidToken(t *testing.T) {
	t.Parallel()

	secret := "my-bootstrap-token-12345"
	hash := HashToken(secret)

	cfg, _ := json.Marshal(Config{TokenHash: hash})
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"authorization", "Bearer "+secret,
	))

	id, err := p.Authenticate(ctx)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if id.Name != "bearer-token" {
		t.Errorf("Name = %q", id.Name)
	}
	if id.Meta["provider"] != "token" {
		t.Errorf("Meta[provider] = %q", id.Meta["provider"])
	}
}

func TestAuthenticate_InvalidToken(t *testing.T) {
	t.Parallel()

	hash := HashToken("correct-token")
	cfg, _ := json.Marshal(Config{TokenHash: hash})
	p, _ := New(cfg)

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"authorization", "Bearer wrong-token",
	))

	_, err := p.Authenticate(ctx)
	if err == nil {
		t.Error("expected error for invalid token")
	}
}

func TestAuthenticate_NoMetadata(t *testing.T) {
	t.Parallel()

	hash := HashToken("token")
	cfg, _ := json.Marshal(Config{TokenHash: hash})
	p, _ := New(cfg)

	_, err := p.Authenticate(context.Background())
	if err == nil {
		t.Error("expected error for missing metadata")
	}
}

func TestAuthenticate_NoAuthHeader(t *testing.T) {
	t.Parallel()

	hash := HashToken("token")
	cfg, _ := json.Marshal(Config{TokenHash: hash})
	p, _ := New(cfg)

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"other-header", "value",
	))

	_, err := p.Authenticate(ctx)
	if err == nil {
		t.Error("expected error for missing authorization header")
	}
}

func TestAuthenticate_WrongScheme(t *testing.T) {
	t.Parallel()

	hash := HashToken("token")
	cfg, _ := json.Marshal(Config{TokenHash: hash})
	p, _ := New(cfg)

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"authorization", "Basic dXNlcjpwYXNz",
	))

	_, err := p.Authenticate(ctx)
	if err == nil {
		t.Error("expected error for non-Bearer scheme")
	}
}

func TestAuthenticate_LowercaseBearer(t *testing.T) {
	t.Parallel()

	secret := "my-token"
	hash := HashToken(secret)
	cfg, _ := json.Marshal(Config{TokenHash: hash})
	p, _ := New(cfg)

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"authorization", "bearer "+secret,
	))

	_, err := p.Authenticate(ctx)
	if err != nil {
		t.Fatalf("Authenticate with lowercase bearer: %v", err)
	}
}

func TestNew_MissingHash(t *testing.T) {
	t.Parallel()

	_, err := New([]byte(`{}`))
	if err == nil {
		t.Error("expected error for missing token_hash")
	}
}

func TestNew_InvalidHash(t *testing.T) {
	t.Parallel()

	_, err := New([]byte(`{"token_hash": "sha256:not-hex"}`))
	if err == nil {
		t.Error("expected error for invalid hex")
	}
}

func TestNew_NilConfig(t *testing.T) {
	t.Parallel()

	_, err := New(nil)
	if err == nil {
		t.Error("expected error for nil config")
	}
}

func TestHashToken(t *testing.T) {
	t.Parallel()

	h := HashToken("test")
	if h[:7] != "sha256:" {
		t.Errorf("hash should start with sha256:, got %q", h[:7])
	}
	if len(h) != 7+64 {
		t.Errorf("hash length = %d, want %d", len(h), 7+64)
	}

	h2 := HashToken("test")
	if h != h2 {
		t.Error("same input should produce same hash")
	}

	h3 := HashToken("different")
	if h == h3 {
		t.Error("different input should produce different hash")
	}
}

func TestName(t *testing.T) {
	t.Parallel()

	hash := HashToken("x")
	cfg, _ := json.Marshal(Config{TokenHash: hash})
	p, _ := New(cfg)
	if p.Name() != "token" {
		t.Errorf("Name = %q", p.Name())
	}
}

func FuzzAuthenticate(f *testing.F) {
	f.Add("Bearer correct-token")
	f.Add("Bearer wrong")
	f.Add("bearer correct-token")
	f.Add("")
	f.Add("Basic dXNlcjpwYXNz")
	f.Add("Bearer ")
	f.Add("Bearer")
	f.Add("bearer")
	f.Add(string(make([]byte, 10000)))
	f.Add("\x00\xff\xfe")
	f.Add("Bearer \x00\x00\x00")

	hash := HashToken("correct-token")
	cfg, _ := json.Marshal(Config{TokenHash: hash})
	p, err := New(cfg)
	if err != nil {
		f.Fatalf("New: %v", err)
	}

	f.Fuzz(func(t *testing.T, authHeader string) {
		ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
			"authorization", authHeader,
		))

		id, err := p.Authenticate(ctx)
		if err != nil {
			return
		}
		if id.Name == "" {
			t.Error("successful auth returned empty identity name")
		}
	})
}

func FuzzNew_Config(f *testing.F) {
	f.Add([]byte(`{"token_hash": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{"token_hash": ""}`))
	f.Add([]byte(`{"token_hash": "not-hex"}`))
	f.Add([]byte(`{"token_hash": "sha256:zzzz"}`))
	f.Add([]byte(`invalid json`))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, cfg []byte) {
		p, err := New(cfg)
		if err != nil {
			return
		}
		if p == nil {
			t.Fatal("nil provider without error")
		}
		if p.Name() != "token" {
			t.Errorf("Name = %q", p.Name())
		}
	})
}
