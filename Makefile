GO ?= go
BIN_DIR ?= bin

.PHONY: all build test vet smoke smoke-direct smoke-relay release-windows verify-release-windows clean

all: test build

build:
	mkdir -p $(BIN_DIR)
	$(GO) build -trimpath -o $(BIN_DIR)/wd ./cmd/wd
	$(GO) build -trimpath -o $(BIN_DIR)/wd-agent ./cmd/wd-agent
	$(GO) build -trimpath -o $(BIN_DIR)/wd-relay ./cmd/wd-relay

test:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

smoke: smoke-direct smoke-relay

smoke-direct:
	./scripts/smoke-direct.sh

smoke-relay:
	./scripts/smoke-relay.sh

release-windows:
	./scripts/build-windows-release.sh

verify-release-windows:
	./scripts/verify-windows-release-repro.sh

clean:
	rm -rf $(BIN_DIR) dist
