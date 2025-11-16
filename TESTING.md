# API Gateway Testing Guide

This document provides comprehensive information about testing the API Gateway, including unit tests, integration tests, load tests, and security tests.

## Table of Contents

1. [Overview](#overview)
2. [Running Tests](#running-tests)
3. [Unit Tests](#unit-tests)
4. [Integration Tests](#integration-tests)
5. [Load Testing](#load-testing)
6. [Security Testing](#security-testing)
7. [Test Coverage](#test-coverage)
8. [Continuous Integration](#continuous-integration)

---

## Overview

The API Gateway test suite implements Phase 12 of the design specification and includes:

- **Unit Tests**: Test individual components in isolation
- **Integration Tests**: Test end-to-end request flows through the middleware pipeline
- **Load Tests**: Validate throughput and latency targets
- **Security Tests**: Verify security hardening and sensitive data redaction

### Performance Targets

Based on `API_GATEWAY_DESIGN.md`, the gateway should meet these targets:

- **Throughput**: >10,000 requests/second per instance
- **Latency**: Gateway overhead <10ms
- **P99 Latency**: <500ms
- **Resource Usage**: Efficient memory and CPU utilization

---

## Running Tests

### Run All Tests

```bash
cargo test
```

### Run Tests with Output

```bash
cargo test -- --nocapture
```

### Run Specific Test File

```bash
# Run authentication tests
cargo test --test auth_test

# Run integration tests
cargo test --test integration_test

# Run rate limiter tests
cargo test --test rate_limiter_test
```

### Run Specific Test

```bash
cargo test test_valid_hs256_token
```

### Run Tests in Release Mode

```bash
cargo test --release
```

---

## Unit Tests

Unit tests verify individual components in isolation. Each module has dedicated unit tests.

### Rate Limiter Tests

**File**: `tests/rate_limiter_test.rs`

Tests cover:
- Key type parsing and validation
- Rate limit decision making
- Header generation
- Context creation with various IP formats
- Edge cases (IPv6, special characters, etc.)

```bash
cargo test --test rate_limiter_test
```

### Routing Tests

**File**: `tests/routing_test.rs`

Tests cover:
- Exact path matching
- Prefix matching (wildcards)
- Template matching with parameters
- Multiple parameters extraction
- Route priority ordering
- Edge cases (trailing slashes, special characters)

```bash
cargo test --test routing_test
```

### Authentication Tests

**File**: `tests/auth_test.rs`

Tests cover:
- JWT token validation (HS256)
- Expired token rejection
- Invalid signature detection
- Issuer validation
- Audience validation

```bash
cargo test --test auth_test
```

### Security Tests

**File**: `tests/security_test.rs`

Tests cover:
- Sensitive data redaction (tokens, passwords, API keys)
- Email address partial redaction
- IP address redaction
- Header sensitivity detection
- Bearer token redaction
- Cookie value redaction

```bash
cargo test --test security_test
```

### Middleware Tests

**File**: `tests/middleware_pipeline_test.rs`

Tests cover:
- Correlation ID generation and propagation
- Client IP extraction
- UUID format validation
- Edge cases (IPv6, localhost, special characters)

```bash
cargo test --test middleware_pipeline_test
```

---

## Integration Tests

Integration tests verify end-to-end request flows through the complete middleware pipeline.

### Authorization End-to-End Tests

**File**: `tests/authorization_e2e_test.rs`

Tests cover:
- RBAC (Role-Based Access Control) authorization
- PBAC (Permission-Based Access Control) authorization
- Combined RBAC and PBAC
- Multiple roles and permissions
- Authorization failures
- Route configuration integration

```bash
cargo test --test authorization_e2e_test
```

### Authentication Integration Tests

**File**: `tests/auth_integration_test.rs`

Tests cover:
- Complete authentication flow
- Token validation with user context
- Expired token handling
- Invalid signature detection
- Issuer and audience validation
- User context serialization

```bash
cargo test --test auth_integration_test
```

### Rate Limiting Integration Tests

**File**: `tests/rate_limiting_integration_test.rs`

Tests cover:
- Rate limit policy configuration
- Different key types (IP, user, endpoint, composite)
- Token bucket algorithm
- Sliding window algorithm
- Burst capacity
- Policy serialization/deserialization
- Edge cases (zero limits, very short/long windows)

```bash
cargo test --test rate_limiting_integration_test
```

### Token Validation Tests

**File**: `tests/token_validation_test.rs`

Tests cover:
- JWT token validation
- Token caching
- Cache invalidation
- Opaque token validation (requires Redis)

```bash
cargo test --test token_validation_test
```

---

## Load Testing

Load testing validates that the gateway meets performance targets.

### Prerequisites

Install one of the following load testing tools:

**Apache Bench (ab)**:
```bash
sudo apt-get install apache2-utils
```

**hey** (recommended for detailed metrics):
```bash
go install github.com/rakyll/hey@latest
```

**wrk** (recommended for high concurrency):
```bash
sudo apt-get install wrk
```

### Running Load Tests

The provided `load-test.sh` script supports multiple load testing tools.

**Basic usage**:
```bash
./load-test.sh [target-url] [tool]
```

**Examples**:

```bash
# Test health endpoint with Apache Bench
./load-test.sh http://localhost:8080/health/live ab

# Test with hey (10,000 requests, 100 concurrent)
./load-test.sh http://localhost:8080/health/live hey

# Test with wrk (30 seconds, 100 concurrent connections)
./load-test.sh http://localhost:8080/health/live wrk

# Simple sequential test with curl
./load-test.sh http://localhost:8080/health/live curl
```

### Interpreting Results

**Throughput**:
- Target: >10,000 requests/second
- Look for "Requests per second" in output

**Latency**:
- Target: <10ms gateway overhead
- Look for "mean" or "average" latency
- Check P99 (99th percentile) latency

**Error Rate**:
- Target: 0% errors under normal load
- Look for "Failed requests" or error percentage

### Load Testing Scenarios

**Scenario 1: Health Check Baseline**
```bash
./load-test.sh http://localhost:8080/health/live ab
```
- Tests minimal gateway overhead
- Should show highest throughput

**Scenario 2: Authenticated Endpoint**
```bash
# Requires valid JWT token
TOKEN="your-jwt-token-here"
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/protected
```

**Scenario 3: Rate Limited Endpoint**
- Test rate limiting by exceeding configured limits
- Should see 429 responses when limit is exceeded

**Scenario 4: Sustained Load**
```bash
./load-test.sh http://localhost:8080/health/ready wrk
```
- 30 second sustained load test
- Monitors for performance degradation over time

---

## Security Testing

Security tests verify that sensitive data is properly protected.

### Running Security Tests

```bash
cargo test --test security_test
```

### Security Test Coverage

**Sensitive Data Redaction**:
- Bearer tokens (show first 4 chars only)
- API keys (fully redacted)
- Passwords (fully redacted)
- Session tokens (fully redacted)
- Email addresses (partially redacted: `u***@example.com`)
- IP addresses (last two octets redacted for IPv4)

**Header Security**:
- Authorization headers
- Cookie headers
- API key headers
- Session token headers

### Manual Security Testing

**Test 1: Token Redaction in Logs**
```bash
# Monitor logs while making authenticated request
tail -f logs/gateway.log | grep -i "authorization"
```
Verify that full token values are NOT present in logs.

**Test 2: Invalid Token Rejection**
```bash
curl -H "Authorization: Bearer invalid-token" \
  http://localhost:8080/api/protected
```
Should return 401 Unauthorized.

**Test 3: CORS and Security Headers**
```bash
curl -I http://localhost:8080/health/live
```
Verify presence of security headers:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Strict-Transport-Security` (if HTTPS)

**Test 4: Rate Limit Bypass Attempt**
```bash
# Rapidly send requests to trigger rate limiting
for i in {1..200}; do
  curl http://localhost:8080/api/endpoint &
done
wait
```
Should see 429 responses after limit is exceeded.

---

## Test Coverage

### Checking Test Coverage

While Rust doesn't have built-in coverage tools, you can use `cargo-tarpaulin`:

**Install**:
```bash
cargo install cargo-tarpaulin
```

**Run coverage**:
```bash
cargo tarpaulin --out Html --output-dir coverage
```

**View results**:
```bash
# Open coverage/index.html in browser
firefox coverage/index.html
```

### Coverage Targets

Per Phase 12 requirements:
- **Unit Test Coverage**: >80% code coverage
- **Critical Paths**: 100% coverage for authentication, authorization, rate limiting

### Current Test Coverage

```
Module                          Coverage
-----------------------------------------
src/auth.rs                     [Excellent]
src/rate_limiter.rs            [Excellent]
src/routing.rs                 [Excellent]
src/middleware.rs              [Good]
src/config.rs                  [Good]
src/error.rs                   [Good]
src/logging.rs                 [Excellent]
src/metrics.rs                 [Good]
```

---

## Continuous Integration

### GitHub Actions

The CI pipeline (`.github/workflows/ci.yml`) runs on every push and PR:

1. **Test Job**: Runs `cargo test --verbose`
2. **Format Job**: Checks code formatting with `cargo fmt`
3. **Clippy Job**: Runs linter with `cargo clippy`
4. **Build Job**: Builds the project with `cargo build`

### Pre-Commit Checklist

Before committing, run:

```bash
# Format code
cargo fmt --all

# Check for clippy warnings
cargo clippy --all-targets --all-features -- -D warnings

# Run all tests
cargo test --verbose

# Build project
cargo build --verbose

# (Optional) Security audit
cargo audit
```

Or use the convenience script:

```bash
# Run all pre-commit checks
./pre-commit-check.sh
```

---

## Test Organization

### Directory Structure

```
api-gateway-rust/
├── src/
│   ├── auth.rs              (Auth module with inline tests)
│   ├── rate_limiter.rs      (Rate limiter with inline tests)
│   ├── routing.rs           (Routing with inline tests)
│   └── ...
├── tests/
│   ├── auth_test.rs         (Auth unit tests)
│   ├── auth_integration_test.rs
│   ├── authorization_e2e_test.rs
│   ├── integration_test.rs
│   ├── middleware_pipeline_test.rs
│   ├── rate_limiter_test.rs
│   ├── rate_limiting_integration_test.rs
│   ├── routing_test.rs
│   ├── security_test.rs
│   └── token_validation_test.rs
├── load-test.sh             (Load testing script)
└── TESTING.md               (This file)
```

### Test Naming Conventions

- **Unit tests**: `test_<functionality>`
  - Example: `test_valid_hs256_token`

- **Integration tests**: `test_<feature>_<scenario>`
  - Example: `test_authentication_flow_success`

- **E2E tests**: `test_e2e_<feature>_<scenario>`
  - Example: `test_e2e_rbac_authorization_success`

---

## Troubleshooting

### Common Issues

**Issue**: Tests fail with "connection refused"
```
Solution: Ensure Redis is running for rate limiting tests
$ docker run -d -p 6379:6379 redis:latest
```

**Issue**: Load test script fails with "command not found"
```
Solution: Install the required load testing tool (ab, hey, or wrk)
$ sudo apt-get install apache2-utils
```

**Issue**: Clippy warnings fail CI
```
Solution: Run clippy locally and fix all warnings
$ cargo clippy --all-targets --all-features -- -D warnings
```

**Issue**: Tests are slow
```
Solution: Run tests in parallel (default) and use release mode for load tests
$ cargo test --release
```

---

## Best Practices

1. **Write tests first**: Follow TDD when adding new features
2. **Test edge cases**: Include tests for boundary conditions
3. **Use descriptive names**: Test names should clearly indicate what is being tested
4. **Keep tests independent**: Each test should be able to run in isolation
5. **Mock external dependencies**: Use test fixtures instead of real services when possible
6. **Test error paths**: Ensure error handling is thoroughly tested
7. **Measure performance**: Use load tests to catch performance regressions
8. **Security testing**: Always test security features (auth, redaction, etc.)

---

## References

- **API Gateway Design**: See `API_GATEWAY_DESIGN.md` for architecture and design
- **Project Instructions**: See `CLAUDE.md` for development guidelines
- **Rust Testing**: https://doc.rust-lang.org/book/ch11-00-testing.html
- **Load Testing with hey**: https://github.com/rakyll/hey
- **Apache Bench**: https://httpd.apache.org/docs/2.4/programs/ab.html

---

## Contributing

When adding new features:

1. Write unit tests for individual components
2. Write integration tests for feature workflows
3. Update this document if new test types are added
4. Ensure all tests pass before submitting PR
5. Aim for >80% code coverage

For questions or issues with tests, please open an issue in the project repository.
