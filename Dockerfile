# Build stage
FROM golang:1.26-alpine AS builder

RUN apk add --no-cache make

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
RUN make build-daemon VERSION=${VERSION}


# Runtime stage
FROM gcr.io/distroless/static:nonroot

COPY --from=builder /src/build/miraged /usr/local/bin/miraged

# Phishlets, redirectors, config, and database are operator-supplied at runtime.
# Mount them as volumes:
#   /etc/mirage/miraged.yaml   — config file
#   /etc/mirage/phishlets/     — phishlet YAML files
#   /etc/mirage/redirectors/   — redirector files
#   /var/lib/mirage/           — SQLite database and generated certs
VOLUME ["/etc/mirage", "/var/lib/mirage"]

# HTTPS proxy (443) and DNS (53/udp).
# Binding privileged ports requires NET_BIND_SERVICE capability:
#   docker run --cap-add NET_BIND_SERVICE ...
EXPOSE 443
EXPOSE 53/udp

ENTRYPOINT ["/usr/local/bin/miraged"]
