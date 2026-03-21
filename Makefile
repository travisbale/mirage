VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-X main.Version=$(VERSION)"

.PHONY: build build-daemon scripts sidecar-install clean test unit fmt lint docker

scripts:
	@echo "Minifying injected JavaScript..."
	@go run ./tools/minify

sidecar-install:
	@echo "Installing obfuscator sidecar dependencies..."
	@cd internal/obfuscator/sidecar && npm ci --omit=dev

build: scripts
	@echo "Building production binaries..."
	@mkdir -p build
	@go build $(LDFLAGS) -o build/miraged ./cmd/miraged
	@go build $(LDFLAGS) -o build/mirage ./cmd/mirage
	@echo "  build/miraged"
	@echo "  build/mirage"

build-daemon: scripts
	@echo "Building miraged..."
	@mkdir -p build
	@go build $(LDFLAGS) -o build/miraged ./cmd/miraged
	@echo "  build/miraged"

clean:
	@echo "Cleaning build artifacts..."
	@rm -rf build/
	@rm -rf internal/proxy/dist/

test: scripts
	@echo "Running all tests (unit + integration)..."
	@go test -tags=integration -count=1 -timeout=120s ./...

unit: scripts
	@echo "Running unit tests..."
	@go test ./...

fmt:
	@echo "Formatting code..."
	@go fmt ./...
	@go run golang.org/x/tools/cmd/goimports@v0.38.0 -w .

lint:
	@echo "Linting code..."
	@docker run -t --rm -v $(shell pwd):/app -w /app golangci/golangci-lint:v2.11 golangci-lint run

docker:
	@echo "Building Docker image..."
	@docker build --build-arg VERSION=$(VERSION) -t mirage:$(VERSION) .
	@echo "  mirage:$(VERSION)"
