# ── Build stage ────────────────────────────────────────────────────────────────
# golang:1.25-alpine gives us the exact Go version from go.mod without the full
# Debian toolchain. The only build dependency beyond the standard library is
# github.com/lib/pq, which is already in go.sum.
FROM golang:1.25-alpine AS builder

WORKDIR /src

# Copy manifests first. The module download layer is cached separately from
# source code so that editing a .go file does not re-download all dependencies.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO_ENABLED=0 produces a fully static binary with the pure-Go net resolver.
# Without it, Alpine's musl libc is not ABI-compatible with the cgo net package,
# causing DNS resolution failures at runtime.
RUN CGO_ENABLED=0 GOOS=linux go build -o /asm-engine ./cmd/asm

# ── Runtime stage ───────────────────────────────────────────────────────────────
# alpine:3.20 is ~7 MB. ca-certificates is required for HTTPS requests to
# crt.sh, HackerTarget, Wayback Machine, and cloud storage endpoints.
FROM alpine:3.20

RUN apk add --no-cache ca-certificates

COPY --from=builder /asm-engine /usr/local/bin/asm-engine

EXPOSE 8080

# Default: start the web UI. Override CMD to run a one-shot CLI scan:
#   docker run asm-engine --target example.com --db <dsn>
ENTRYPOINT ["asm-engine"]
CMD ["--ui"]
