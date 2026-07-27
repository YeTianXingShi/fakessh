# syntax=docker/dockerfile:1.7
FROM --platform=$BUILDPLATFORM golang:1.24.0-alpine AS builder
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go test ./... && \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/fakessh ./cmd/fakessh

FROM alpine:3.22
RUN apk add --no-cache ca-certificates && \
    addgroup -S -g 10001 fakessh && adduser -S -D -H -u 10001 -G fakessh fakessh && \
    mkdir -p /data && chown fakessh:fakessh /data
COPY --from=builder /out/fakessh /usr/local/bin/fakessh
USER 10001:10001
EXPOSE 2222 8080
VOLUME ["/data"]
ENV SSH_LISTEN_ADDR=:2222 WEB_LISTEN_ADDR=:8080 DATA_DIR=/data LOG_LEVEL=info
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -q -O - http://127.0.0.1:8080/healthz >/dev/null || exit 1
ENTRYPOINT ["/usr/local/bin/fakessh"]
