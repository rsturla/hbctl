# Authentication

## Providers

Authentication is pluggable via the `authn.Registry`. Set `HB_AUTH_METHOD` to select.

### mTLS (default)

Identity extracted from the client certificate's Subject:

- **Name** — Common Name (CN)
- **Groups** — Organization (O)

```
HB_AUTH_METHOD=mtls
```

Every connection must present a client certificate signed by the agent's CA. TLS 1.3 minimum, ECDSA P-256 keys.

### Token

Bearer token in gRPC metadata. Token is never stored — only its SHA-256 hash.

```
HB_AUTH_METHOD=token
HB_AUTH_CONFIG={"token_hash":"sha256:<hex>"}
```

Use `hbctl gen-token` to generate a token and its hash.

### Adding Providers

Implement the `authn.Authenticator` interface:

```go
type Authenticator interface {
    Name() string
    Authenticate(ctx context.Context) (Identity, error)
}
```

Register in main.go:

```go
registry.Register("oidc", oidc.New)
```

## Bootstrap Flow

New nodes need client credentials. The bootstrap flow issues them securely:

```
Operator                                          Node (hb-agent)
  │                                                  │
  │  hbctl gen-token → token + hash                  │
  │  deliver hash to node (cloud-init, PXE, etc.)   │
  │                                                  │  reads hash from
  │                                                  │  /var/lib/hummingbird/pki/bootstrap-token-hash
  │                                                  │
  │  hbctl bootstrap                                 │
  │    --endpoint 10.0.0.5:50000                     │
  │    --token <token>                               │
  │    --ca-fingerprint sha256:<hex>                  │
  │    --output-dir ~/.hbctl/nodes/10.0.0.5/         │
  │                                                  │
  │  1. generate ECDSA P-256 keypair locally         │
  │  2. create CSR (public key only)                 │
  │  3. connect with TLS (verify server fingerprint) │
  │  4. send token + CSR ─────────────────────────>  │
  │                                                  │  5. verify token (constant-time)
  │                                                  │  6. verify CSR signature
  │                                                  │  7. override CSR Subject (assign identity)
  │                                                  │  8. sign cert with CA
  │                                                  │  9. delete token hash (one-time use)
  │  <───────────── ca.crt + signed client cert ──── │
  │                                                  │
  │  10. write ca.crt, client.crt, client.key        │
  │  Private key never left the operator's machine   │
```

### Security Properties

- **CSR-based** — private key never leaves the client
- **One-time token** — consumed on first successful use, deleted from disk
- **Rate limited** — 3 failed attempts, then lockout (token hash deleted)
- **Fingerprint required** — no TOFU, server identity verified out-of-band
- **Subject overridden** — agent assigns identity, ignores client-requested CN/Org
- **Generic errors** — failed attempts return "authentication failed" (no attempt count)
