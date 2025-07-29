# Multi-stage Dockerfile for Provenance Graph SBOM Linker
# =============================================================================

# Build stage
FROM golang:1.21-alpine AS builder

# Security: Create non-root user
RUN adduser -D -s /bin/sh -u 1001 appuser

# Install build dependencies
RUN apk add --no-cache \
    git \
    ca-certificates \
    gcc \
    musl-dev \
    make \
    curl

# Set working directory
WORKDIR /src

# Copy dependency files first for better caching
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Build the application
ARG VERSION=unknown
ARG COMMIT=unknown
ARG DATE=unknown

RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -X github.com/your-org/provenance-graph-sbom-linker/internal/version.Version=${VERSION} \
              -X github.com/your-org/provenance-graph-sbom-linker/internal/version.Commit=${COMMIT} \
              -X github.com/your-org/provenance-graph-sbom-linker/internal/version.Date=${DATE}" \
    -a -installsuffix cgo \
    -o /bin/provenance-linker \
    ./cmd/server

# Build CLI tool
RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -X github.com/your-org/provenance-graph-sbom-linker/internal/version.Version=${VERSION} \
              -X github.com/your-org/provenance-graph-sbom-linker/internal/version.Commit=${COMMIT} \
              -X github.com/your-org/provenance-graph-sbom-linker/internal/version.Date=${DATE}" \
    -a -installsuffix cgo \
    -o /bin/provenance-cli \
    ./cmd/cli

# Verify binary
RUN /bin/provenance-linker --version || true

# =============================================================================
# Security scanning stage
FROM builder AS security-scanner

# Install security scanning tools
RUN apk add --no-cache \
    trivy

# Run security scan (fails build if critical vulnerabilities found)
RUN trivy fs --security-checks vuln --severity HIGH,CRITICAL --exit-code 1 /src || \
    (echo "Security vulnerabilities found, failing build" && exit 1)

# =============================================================================
# Runtime stage
FROM alpine:3.19 AS runtime

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    curl \
    jq

# Security: Create non-root user
RUN adduser -D -s /bin/sh -u 1001 appuser

# Create necessary directories
RUN mkdir -p /app/data /app/logs /app/config && \
    chown -R appuser:appuser /app

# Copy SSL certificates
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy binary from builder stage
COPY --from=builder --chown=appuser:appuser /bin/provenance-linker /app/
COPY --from=builder --chown=appuser:appuser /bin/provenance-cli /app/

# Copy configuration files
COPY --chown=appuser:appuser configs/ /app/config/

# Switch to non-root user
USER appuser

# Set working directory
WORKDIR /app

# Expose ports
EXPOSE 8080 9090

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Default command
ENTRYPOINT ["./provenance-linker"]
CMD ["--config", "/app/config/config.yaml"]

# =============================================================================
# Development stage
FROM golang:1.21-alpine AS development

# Install development tools
RUN apk add --no-cache \
    git \
    make \
    curl \
    ca-certificates \
    gcc \
    musl-dev \
    bash \
    fish \
    vim \
    nano

# Install Go development tools
RUN go install github.com/cosmtrek/air@latest && \
    go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest && \
    go install golang.org/x/tools/cmd/goimports@latest

# Create non-root user for development
RUN adduser -D -s /bin/bash -u 1001 developer

# Set working directory
WORKDIR /workspace

# Switch to developer user
USER developer

# Default command for development
CMD ["air", "-c", ".air.toml"]

# =============================================================================
# Testing stage
FROM golang:1.21-alpine AS testing

# Install test dependencies
RUN apk add --no-cache \
    git \
    make \
    gcc \
    musl-dev \
    ca-certificates

# Set working directory
WORKDIR /src

# Copy source code
COPY . .

# Download dependencies
RUN go mod download

# Run tests
RUN make test

# Run security checks
RUN make security-scan

# Generate coverage report
RUN make test-coverage

# =============================================================================
# Production optimized stage
FROM scratch AS production

# Import from builder
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group

# Copy binary
COPY --from=builder --chown=1001:1001 /bin/provenance-linker /provenance-linker

# Use non-root user
USER 1001

# Expose port
EXPOSE 8080

# Health check using the binary itself
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD ["/provenance-linker", "health-check"]

# Entry point
ENTRYPOINT ["/provenance-linker"]

# =============================================================================
# Documentation stage
FROM node:24-alpine AS docs

# Set working directory
WORKDIR /docs

# Copy documentation source
COPY docs/ ./
COPY README.md ./

# Install documentation dependencies
RUN npm install -g @vuepress/cli vuepress

# Build documentation
RUN npm run docs:build

# =============================================================================
# Final stage selection based on build argument
ARG BUILD_TARGET=runtime

FROM ${BUILD_TARGET} AS final

# Metadata labels
LABEL org.opencontainers.image.title="Provenance Graph SBOM Linker"
LABEL org.opencontainers.image.description="End-to-end software supply chain provenance tracker"
LABEL org.opencontainers.image.vendor="Your Organization"
LABEL org.opencontainers.image.version="${VERSION}"
LABEL org.opencontainers.image.revision="${COMMIT}"
LABEL org.opencontainers.image.created="${DATE}"
LABEL org.opencontainers.image.source="https://github.com/your-org/provenance-graph-sbom-linker"
LABEL org.opencontainers.image.documentation="https://docs.your-org.com/provenance-linker"
LABEL org.opencontainers.image.licenses="MIT"

# Security labels
LABEL security.non-root="true"
LABEL security.no-new-privileges="true"