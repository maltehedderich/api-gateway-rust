# Multi-stage Dockerfile for API Gateway
# Stage 1: Build
FROM rust:1.75-bookworm as builder

# Create app directory
WORKDIR /usr/src/api-gateway-rust

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY src ./src
COPY tests ./tests

# Build for release
RUN cargo build --release --verbose

# Strip the binary to reduce size
RUN strip target/release/api-gateway-rust

# Stage 2: Runtime
FROM debian:bookworm-slim

# Install CA certificates and other runtime dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user
RUN useradd -m -u 1000 -s /bin/bash gateway

# Create app directory
WORKDIR /app

# Copy the binary from builder
COPY --from=builder /usr/src/api-gateway-rust/target/release/api-gateway-rust /app/api-gateway-rust

# Copy example configuration (can be overridden via volume mount)
COPY config.example.yaml /app/config.yaml

# Change ownership to non-root user
RUN chown -R gateway:gateway /app

# Switch to non-root user
USER gateway

# Expose ports
# 8080: HTTP/HTTPS traffic
# 9090: Metrics endpoint
EXPOSE 8080 9090

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health/live || exit 1

# Set entrypoint
ENTRYPOINT ["/app/api-gateway-rust"]

# Default command arguments (can be overridden)
CMD ["--config", "/app/config.yaml"]
