# Multi-stage Dockerfile for API Gateway Rust Lambda Function
# Optimized for AWS Lambda with custom runtime

# ========================================
# Stage 1: Build
# ========================================
FROM rust:1.75-bullseye as builder

# Install dependencies for cross-compilation and Lambda runtime
RUN apt-get update && \
    apt-get install -y \
        musl-tools \
        pkg-config \
        libssl-dev \
        && rm -rf /var/lib/apt/lists/*

# Create a new user to run the build (security best practice)
RUN useradd -m -u 1001 -U builder
USER builder
WORKDIR /home/builder/app

# Copy dependency files first for better caching
COPY --chown=builder:builder Cargo.toml Cargo.lock ./

# Copy source code
COPY --chown=builder:builder src ./src

# Build the application in release mode
RUN cargo build --release

# ========================================
# Stage 2: Lambda Runtime
# ========================================
FROM public.ecr.aws/lambda/provided:al2023

# Install AWS Lambda Runtime Interface Emulator and runtime dependencies
RUN yum install -y ca-certificates && \
    yum clean all && \
    rm -rf /var/cache/yum

# Copy the compiled binary from builder stage
COPY --from=builder /home/builder/app/target/release/api-gateway-rust ${LAMBDA_RUNTIME_DIR}/bootstrap

# Copy Lambda runtime adapter (allows standard HTTP server to work on Lambda)
# This adapter makes the Rust HTTP server compatible with Lambda
COPY --from=public.ecr.aws/awsguru/aws-lambda-adapter:0.8.1 /lambda-adapter ${LAMBDA_RUNTIME_DIR}/extensions/

# Set executable permissions
RUN chmod +x ${LAMBDA_RUNTIME_DIR}/bootstrap

# Environment variables for Lambda adapter
# The adapter translates Lambda events to HTTP requests on port 8080
ENV PORT=8080
ENV READINESS_CHECK_PORT=8080
ENV READINESS_CHECK_PATH=/health/ready
ENV ASYNC_INIT=true

# Lambda handler (not used with custom runtime, but required)
CMD ["bootstrap"]
