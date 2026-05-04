# hbctl

Hummingbird node management agent (`hb-agent`) and CLI (`hbctl`) for bootc-based immutable OS images.

## Repository Layout

```
cmd/hb-agent/      Agent entrypoint
cmd/hbctl/         CLI client
internal/          Core packages (handler, authn, authz, health, pki, etc.)
plugins/           Plugin implementations (services, diagnostics, lifecycle, config)
api/proto/         Protobuf service definitions
docs/              Documentation
```

## Key Patterns

- **Registry pattern** — used for authn, authz, and plugins. All use explicit `Registry` structs with `Register(name, factory)` / `Create(name, cfg)`.
- **Auth-by-default** — every RPC uses `handler.Unary` or `handler.ServerStream` which requires a typed `authz.Resource` extractor. `nil` authorizer = deny. Handlers never touch auth directly.
- **Input validation** — `internal/validate/` package. All user inputs validated before system commands. Use it for any new user-facing input.
- **Typed resources** — `authz.Resource` with types: Node, Service, Image, Config, Path. Cedar policies reference these types.

## Build

```bash
make build       # build both binaries
make test-race   # tests with race detector
make fuzz        # fuzz all targets
make lint        # golangci-lint
make check       # lint + test-race + build (CI entrypoint)
```

## Adding a New RPC

1. Add the RPC to `api/proto/hb/v1alpha1/machine.proto`
2. Run `make proto`
3. Create a handler with `handler.NewUnary` — you MUST provide a resource extractor
4. Add the gRPC adapter method (one-liner calling `Execute`)
5. Add input validation via `internal/validate/`
6. Add tests + fuzz target for any parsing

## Security

- All crypto via Go stdlib `crypto/*` — no third-party crypto
- CSR-based bootstrap — private keys never leave the client
- `clear()` used on all secret byte slices after use
- Never log tokens, keys, or secrets
- Generic error messages to clients — detailed logs server-side only
- See `docs/security.md`

## Testing

- 399+ tests across 22 packages
- 18 fuzz targets covering all security-critical parsing surfaces
- Fuzz runs on every PR (10s), every push to main (60s), weekly (300s)
- Run `make test-count` to see current test count
