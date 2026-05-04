GO       ?= go
PROTOC   ?= protoc
LINT     ?= golangci-lint
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS  := -s -w -X main.version=$(VERSION)

PROTOC_GEN_GO      ?= $(shell $(GO) env GOPATH)/bin/protoc-gen-go
PROTOC_GEN_GO_GRPC ?= $(shell $(GO) env GOPATH)/bin/protoc-gen-go-grpc

FUZZ_TIME ?= 10s

.PHONY: all build test test-race test-count lint fuzz proto proto-check tools check clean

all: lint test build

# ── Build ──

build:
	CGO_ENABLED=0 $(GO) build -ldflags='$(LDFLAGS)' -o bin/hb-agent ./cmd/hb-agent
	CGO_ENABLED=0 $(GO) build -ldflags='$(LDFLAGS)' -o bin/hbctl ./cmd/hbctl

# ── Test ──

test:
	$(GO) test ./...

test-race:
	$(GO) test -race -count=1 ./...

test-count:
	@$(GO) test -v ./... 2>&1 | grep -cE '^\s*--- (PASS|FAIL)'

# ── Fuzz ──

fuzz:
	@echo "discovering fuzz targets..."
	@failed=0; count=0; \
	for pkg in $$($(GO) list ./...); do \
		targets=$$($(GO) test -list '^Fuzz' $$pkg 2>/dev/null | grep '^Fuzz' || true); \
		for target in $$targets; do \
			count=$$((count + 1)); \
			echo "  [$$count] $$target ($$pkg) $(FUZZ_TIME)"; \
			output=$$($(GO) test -fuzz=^$$target$$ -fuzztime=$(FUZZ_TIME) $$pkg 2>&1); \
			if [ $$? -ne 0 ]; then echo "  FAIL: $$target ($$pkg)"; echo "$$output" | tail -20; failed=1; fi; \
		done; \
	done; \
	echo "$$count fuzz targets completed"; \
	exit $$failed

# ── Lint ──

lint:
	$(LINT) run ./...

# ── Proto ──

proto:
	$(PROTOC) \
		--plugin=protoc-gen-go=$(PROTOC_GEN_GO) \
		--plugin=protoc-gen-go-grpc=$(PROTOC_GEN_GO_GRPC) \
		--go_out=internal/gen --go_opt=paths=source_relative \
		--go-grpc_out=internal/gen --go-grpc_opt=paths=source_relative \
		-I api/proto \
		api/proto/hb/v1alpha1/machine.proto

proto-check: proto
	@git diff --exit-code internal/gen/ || { echo "error: proto generated code is out of date — run 'make proto'"; exit 1; }

# ── Tools ──

tools:
	$(GO) install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	$(GO) install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# ── CI entrypoint ──

check: lint test-race build

clean:
	rm -rf bin/
