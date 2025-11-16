# API Gateway - Rust Implementation

A high-performance API Gateway written in Rust, implementing OAuth2 session-based authentication, rate limiting, and request logging.

## Features Implemented

### Stage 1: Connection Handling ✅

- **HTTP/HTTPS Server**: Asynchronous HTTP server with optional TLS support
- **Connection Management**: Efficient connection handling with configurable timeouts
- **Request Parsing**: Robust HTTP request parsing with error handling
- **Health Checks**: Liveness and readiness endpoints for orchestration
- **Structured Logging**: JSON-formatted structured logging with correlation IDs
- **Error Handling**: Comprehensive error handling with client-friendly error responses

## Architecture

The gateway is built using:

- **Tokio**: Async runtime for high-performance I/O
- **Axum**: Modern web framework built on Hyper and Tower
- **Rustls**: Memory-safe TLS implementation
- **Tracing**: Structured logging and diagnostics

## Configuration

The gateway can be configured using environment variables:

| Environment Variable | Description | Default |
|---------------------|-------------|---------|
| `GATEWAY_BIND_ADDRESS` | Address to bind the server | `0.0.0.0` |
| `GATEWAY_PORT` | Port to listen on | `8443` |
| `GATEWAY_TLS_CERT_PATH` | Path to TLS certificate | None (HTTP mode) |
| `GATEWAY_TLS_KEY_PATH` | Path to TLS private key | None (HTTP mode) |
| `GATEWAY_TLS_MIN_VERSION` | Minimum TLS version (1.2 or 1.3) | `1.2` |
| `GATEWAY_CONNECTION_TIMEOUT_SECS` | Connection timeout in seconds | `60` |
| `GATEWAY_MAX_CONNECTIONS` | Maximum concurrent connections | `10000` |
| `GATEWAY_REQUEST_TIMEOUT_SECS` | Request timeout in seconds | `30` |
| `RUST_LOG` | Log level configuration | `info` |

## Running the Gateway

### HTTP Mode (Development)

```bash
# Run without TLS (HTTP only - not for production)
cargo run
```

The server will start on `http://0.0.0.0:8443`

### HTTPS Mode (Production)

```bash
# Set up TLS certificates
export GATEWAY_TLS_CERT_PATH=/path/to/cert.pem
export GATEWAY_TLS_KEY_PATH=/path/to/key.pem

# Run with TLS
cargo run
```

The server will start on `https://0.0.0.0:8443`

### Custom Configuration

```bash
# Customize server settings
export GATEWAY_PORT=8080
export GATEWAY_BIND_ADDRESS=127.0.0.1
export GATEWAY_REQUEST_TIMEOUT_SECS=60
export RUST_LOG=debug

cargo run
```

## Health Check Endpoints

The gateway exposes health check endpoints for monitoring and orchestration:

### Liveness Probe

```bash
curl http://localhost:8443/health/live
```

Returns `200 OK` if the server is running.

### Readiness Probe

```bash
curl http://localhost:8443/health/ready
```

Returns `200 OK` if the server is ready to accept traffic.

## Development

### Building

```bash
# Build in debug mode
cargo build

# Build in release mode (optimized)
cargo build --release
```

### Testing

```bash
# Run unit tests
cargo test

# Run with output
cargo test -- --nocapture

# Run specific test
cargo test test_config_validation
```

### Code Quality

```bash
# Format code
cargo fmt

# Run linter
cargo clippy

# Check for security vulnerabilities
cargo audit
```

## Error Handling

The gateway returns structured JSON error responses:

```json
{
  "error": {
    "code": "bad_request",
    "message": "Invalid request format",
    "correlation_id": "550e8400-e29b-41d4-a716-446655440000",
    "timestamp": "2024-03-15T12:34:56Z"
  }
}
```

Error codes include:
- `bad_request` (400): Malformed HTTP request
- `request_timeout` (408): Connection or request timeout
- `internal_error` (500): Internal server error

## Logging

The gateway uses structured JSON logging. Example log entry:

```json
{
  "timestamp": "2024-03-15T12:34:56.789Z",
  "level": "INFO",
  "target": "api_gateway_rust::server",
  "fields": {
    "message": "Request completed",
    "status": "200",
    "latency_ms": "42"
  }
}
```

Configure log levels with the `RUST_LOG` environment variable:

```bash
# Debug level for the gateway, info for everything else
export RUST_LOG=info,api_gateway_rust=debug

# Trace all networking activity
export RUST_LOG=trace
```

## Project Structure

```
api-gateway-rust/
├── src/
│   ├── main.rs         # Application entry point
│   ├── lib.rs          # Library exports
│   ├── config.rs       # Configuration management
│   ├── error.rs        # Error types and handling
│   └── server.rs       # HTTP server and connection handling
├── tests/
│   └── integration_test.rs  # Integration tests
├── Cargo.toml          # Dependencies and metadata
└── README.md           # This file
```

## Next Stages

The following stages will be implemented in future iterations:

- **Stage 2**: Routing and upstream service forwarding
- **Stage 3**: Request logging with correlation IDs
- **Stage 4**: Session token authentication
- **Stage 5**: Authorization
- **Stage 6**: Rate limiting
- **Stage 7**: Observability and metrics

## Security Considerations

### TLS Configuration

- **Production**: Always use TLS (HTTPS) in production
- **Minimum TLS Version**: TLS 1.2 or higher
- **Certificate Management**: Use valid certificates from trusted CAs
- **Key Security**: Protect private keys with appropriate file permissions

### Connection Limits

- Configure `GATEWAY_MAX_CONNECTIONS` based on your system resources
- Set appropriate timeouts to prevent resource exhaustion
- Monitor connection metrics in production

## Performance

The gateway is designed for high performance:

- **Asynchronous I/O**: Non-blocking operations throughout
- **Connection Pooling**: Efficient connection reuse
- **Low Latency**: Target < 10ms gateway overhead
- **High Throughput**: > 10,000 requests/sec per instance (hardware dependent)

## License

See the design specification for complete architecture details.
