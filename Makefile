GO ?= go
PROTOC ?= protoc
PROTOC_GEN_GO ?= $(shell go env GOPATH)/bin/protoc-gen-go
PROTOC_GEN_GO_GRPC ?= $(shell go env GOPATH)/bin/protoc-gen-go-grpc

.PHONY: proto build test test-race lint clean

proto:
	$(PROTOC) \
		--plugin=protoc-gen-go=$(PROTOC_GEN_GO) \
		--plugin=protoc-gen-go-grpc=$(PROTOC_GEN_GO_GRPC) \
		--go_out=internal/gen --go_opt=paths=source_relative \
		--go-grpc_out=internal/gen --go-grpc_opt=paths=source_relative \
		-I api/proto \
		api/proto/hb/v1alpha1/machine.proto

build:
	CGO_ENABLED=1 $(GO) build -ldflags='-s -w' -o bin/hb-agent ./cmd/hb-agent
	CGO_ENABLED=0 $(GO) build -ldflags='-s -w' -o bin/hbctl ./cmd/hbctl

test:
	$(GO) test ./...

test-race:
	$(GO) test -race -count=1 ./...

lint:
	golangci-lint run ./...

clean:
	rm -rf bin/
