VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-X main.Version=$(VERSION)"

.PHONY: build clean test

build:
	mkdir -p build
	go build $(LDFLAGS) -o build/miraged ./cmd/miraged
	go build $(LDFLAGS) -o build/mirage ./cmd/mirage

clean:
	rm -rf build/

test:
	go test ./...
