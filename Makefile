VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-X main.Version=$(VERSION)"

.PHONY: build clean test fmt lint

build:
	mkdir -p build
	go build $(LDFLAGS) -o build/miraged ./cmd/miraged
	go build $(LDFLAGS) -o build/mirage ./cmd/mirage

clean:
	rm -rf build/

test:
	go test ./...

fmt:
	@echo "Formatting code..."
	@go fmt ./...
	@go run golang.org/x/tools/cmd/goimports@v0.38.0 -w .

lint:
	@echo "Linting code..."
	@docker run -t --rm -v $(shell pwd):/app -w /app golangci/golangci-lint:v2.6.0 golangci-lint run
