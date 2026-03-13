GO := /usr/local/bin/go

.PHONY: build clean test

build:
	mkdir -p build
	$(GO) build -o build/miraged ./cmd/miraged
	$(GO) build -o build/mirage ./cmd/mirage

clean:
	rm -rf build/

test:
	$(GO) test ./...
