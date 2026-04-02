# Build stage
FROM golang:1.26-alpine AS builder

RUN apk add --no-cache make

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
RUN make build VERSION=${VERSION}

# Create the data directory owned by nonroot (UID 65534) so the volume
# inherits the correct permissions when Docker initializes it.
RUN mkdir -p /tmp/mirage-data && chown 65534:65534 /tmp/mirage-data


# Runtime stage
FROM gcr.io/distroless/static:nonroot

COPY --from=builder /src/build/miraged /usr/local/bin/miraged
COPY --from=builder --chown=nonroot:nonroot /tmp/mirage-data /var/lib/mirage

# Config is operator-supplied at runtime as a read-only mount.
#   /etc/mirage/miraged.yaml   — config file
#   /var/lib/mirage/           — SQLite database (includes phishlet definitions) and generated certs
VOLUME ["/etc/mirage", "/var/lib/mirage"]

# HTTPS proxy (443) and DNS (53/udp).
# Binding privileged ports requires NET_BIND_SERVICE capability:
#   docker run --cap-add NET_BIND_SERVICE ...
EXPOSE 443
EXPOSE 53/udp

ENTRYPOINT ["/usr/local/bin/miraged"]
