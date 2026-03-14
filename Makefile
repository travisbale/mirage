VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-X main.Version=$(VERSION)"

.PHONY: build build-daemon clean test fmt lint docker

build:
	@echo "Building production binaries..."
	@mkdir -p build
	@go build $(LDFLAGS) -o build/miraged ./cmd/miraged
	@go build $(LDFLAGS) -o build/mirage ./cmd/mirage

build-daemon:
	@echo "Building miraged..."
	@mkdir -p build
	@go build $(LDFLAGS) -o build/miraged ./cmd/miraged

clean:
	@echo "Cleaning build artifacts..."
	@rm -rf build/

test:
	@echo "Running tests..."
	@go test ./...

fmt:
	@echo "Formatting code..."
	@go fmt ./...
	@go run golang.org/x/tools/cmd/goimports@v0.38.0 -w .

lint:
	@echo "Linting code..."
	@docker run -t --rm -v $(shell pwd):/app -w /app golangci/golangci-lint:v2.6.0 golangci-lint run

docker:
	@echo "Building Docker image..."
	@docker build --build-arg VERSION=$(VERSION) -t mirage:$(VERSION) .
