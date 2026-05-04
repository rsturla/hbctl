# Security

## Threat Model

hb-agent is the sole management interface for immutable, shell-less nodes. Compromise of the agent = full node compromise. The attack surface is:

1. The gRPC API (network-reachable)
2. The bootstrap endpoint (temporary, token-gated)
3. The PKI material on disk

## Transport Security

- TLS 1.3 minimum (`tls.VersionTLS13`)
- ECDSA P-256 keys
- mTLS by default — every connection requires a client certificate
- Server cert includes all node IPs and hostname as SANs (auto-discovered)

## Authentication

See [authentication.md](authentication.md).

- Identity extracted from peer certificate or bearer token
- No anonymous access (except BootstrapAuth)
- Constant-time token comparison (`crypto/subtle`)

## Authorization

See [authorization.md](authorization.md).

- Default deny when no authorizer is configured (nil authorizer = deny)
- Cedar policy engine for per-resource access control
- `allow-all` available for development (emits warning at startup)
- Handler framework enforces auth — handlers cannot bypass it

## Input Validation

All user inputs are validated before reaching system commands:

| Input | Validation | Blocks |
|-------|-----------|--------|
| Unit names | Regex allowlist, `.service`/`.socket`/etc suffix | Path traversal, flag injection |
| Image refs | Format check, rejects `-` prefix, `--` separator in exec | Flag injection |
| Hostnames | RFC 1123 | Newline injection |
| DNS servers | Must parse as IP address | Newline injection, arbitrary resolv.conf directives |
| Interface names | Alphanumeric + `-._`, no `/` or `..` | Path traversal |
| Network config | No newlines in any field | Config file injection |
| Kernel args | Blocks `init=`, `rd.break`, `selinux=0`, `enforcing=0` | Security bypass on reboot |

## Crypto

All cryptographic operations use Go's standard library (`crypto/*`). No third-party crypto dependencies.

**FIPS compliance** works via the Go toolchain:

- **Red Hat/Fedora Go RPM** — ships with `GOEXPERIMENT=opensslcrypto`, automatically delegates to system OpenSSL (FIPS-validated)
- **Upstream Go** — `GOEXPERIMENT=boringcrypto` or `GOEXPERIMENT=systemcrypto` available
- **No experiment** — Go's stdlib crypto still works, just not FIPS-certified

Since hbctl never imports third-party crypto, whichever FIPS backend the distro's Go toolchain provides works transparently.

## Secret Handling

- Private key bytes zeroed with `clear()` after use (CA, server, client keys)
- Token hashes zeroed after comparison
- CA key DER bytes cleared in `Bootstrap()`, `GenerateClientCert()`, `SignCSR()`
- Bootstrap token hash deleted from disk after consumption
- Tokens never logged

## Bootstrap Security

- CSR-based — private key never leaves the client
- One-time token with rate limiting (3 attempts, then lockout)
- Server fingerprint required — no TOFU
- CSR Subject overridden — server assigns identity
- Generic error messages to clients

## Known Limitations

- No certificate revocation (CRL/OCSP) — compromised certs valid until expiry
- gRPC reflection enabled unconditionally
- Bootstrap relaxes mTLS for the entire listener (single listener)
- No audit log (structured security event stream)
- Long cert lifetimes (CA: 10y, server: 5y, client: 1y)
- Bootstrap lockout counter resets on agent restart
