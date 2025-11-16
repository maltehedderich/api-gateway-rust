# API Gateway Rust - Claude AI Assistant Guide

## Project Overview

This is a high-performance API Gateway written in Rust that provides:
- Request logging with structured logs and correlation IDs
- OAuth2-based session authentication and authorization
- Rate limiting with multiple strategies
- Reverse proxy functionality for routing to upstream services

**Reference Document**: See `API_GATEWAY_DESIGN.md` for the complete architecture and design specification.

## Code Quality Standards

### Formatting
- **All code MUST be formatted with `cargo fmt`** before committing
- Run `cargo fmt --all` to format all code
- GitHub Actions will fail if code is not properly formatted

### Linting
- **All clippy warnings MUST be resolved** before committing
- Run `cargo clippy --all-targets --all-features -- -D warnings`
- Clippy is configured to treat warnings as errors in CI
- Common issues to avoid:
  - Unused variables or imports
  - Unnecessary clones or allocations
  - Missing error handling
  - Non-idiomatic Rust patterns

### Testing
- **All tests MUST pass** before committing
- Run `cargo test --verbose` to execute all tests
- Add tests for new functionality
- Maintain or improve test coverage

### Building
- **The project MUST build successfully** without errors
- Run `cargo build --verbose` to verify builds
- Run `cargo build --release --verbose` for release builds

## GitHub Actions Pipelines

### CI Pipeline (.github/workflows/ci.yml)
Runs on every push to main and all pull requests:
1. **Test Job**: Executes `cargo test --verbose`
2. **Format Job**: Checks code formatting with `cargo fmt --all -- --check`
3. **Clippy Job**: Runs linter with `cargo clippy --all-targets --all-features -- -D warnings`
4. **Build Job**: Builds project with `cargo build --verbose`

**To ensure CI passes:**
```bash
# Run these commands before committing
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --verbose
cargo build --verbose
```

### Security Audit Pipeline (.github/workflows/security.yml)
Runs on:
- Pushes to main that modify Cargo.toml or Cargo.lock
- Pull requests that modify Cargo.toml or Cargo.lock
- Daily at 00:00 UTC
- Manual workflow dispatch

**Checks**: Runs `cargo audit` to detect known security vulnerabilities in dependencies

**To ensure security audit passes:**
```bash
# Install cargo-audit
cargo install cargo-audit --locked

# Run security audit
cargo audit

# If vulnerabilities found, update dependencies
cargo update
```

### Release Pipeline (.github/workflows/release.yml)
Runs on version tags (v*.*.*) or manual workflow dispatch:
1. Builds release binary with `cargo build --release`
2. Strips binary with `strip target/release/api-gateway-rust`
3. Creates tarball
4. Uploads artifact

## Development Workflow

### Before Making Changes
1. Read `API_GATEWAY_DESIGN.md` to understand the architecture
2. Ensure you understand the component you're modifying
3. Check existing tests for examples

### While Making Changes
1. Follow Rust idioms and best practices
2. Add inline documentation for public APIs
3. Write tests for new functionality
4. Keep commits focused and atomic

### Before Committing
**Run this pre-commit checklist:**
```bash
# 1. Format code
cargo fmt --all

# 2. Check for clippy warnings
cargo clippy --all-targets --all-features -- -D warnings

# 3. Run tests
cargo test --verbose

# 4. Verify build
cargo build --verbose

# 5. Check for security vulnerabilities (optional but recommended)
cargo audit
```

### Committing Changes
- Write clear, descriptive commit messages
- Reference issue numbers when applicable
- Use conventional commit format when possible:
  - `feat:` for new features
  - `fix:` for bug fixes
  - `docs:` for documentation
  - `test:` for tests
  - `refactor:` for refactoring
  - `chore:` for maintenance

## Common Issues and Solutions

### Clippy Warnings
**Issue**: Clippy warnings causing CI to fail

**Solutions**:
- Run `cargo clippy --all-targets --all-features -- -D warnings` locally
- Fix warnings one by one
- If a warning is a false positive, add `#[allow(clippy::lint_name)]` with justification
- Never disable warnings globally

### Formatting Issues
**Issue**: Code not formatted correctly

**Solutions**:
- Always run `cargo fmt --all` before committing
- Consider setting up a pre-commit hook to run cargo fmt automatically
- Use IDE integration for automatic formatting on save

### Test Failures
**Issue**: Tests failing in CI

**Solutions**:
- Run `cargo test --verbose` locally to reproduce
- Check for environment-specific issues
- Ensure tests are deterministic and don't depend on timing or external state
- Fix failing tests before committing

### Build Failures
**Issue**: Build failing in CI

**Solutions**:
- Run `cargo build --verbose` locally to reproduce
- Check for missing dependencies in Cargo.toml
- Ensure all features compile
- Test with `cargo build --all-targets --all-features`

### Dependency Security Vulnerabilities
**Issue**: cargo-audit finding vulnerabilities

**Solutions**:
- Update vulnerable dependencies: `cargo update -p <package>`
- If no update available, check if vulnerability applies to your usage
- Consider alternative dependencies if needed
- Document any accepted risks

## Architecture and Design Patterns

### Component Structure
The gateway follows a layered architecture:
1. **Network Layer**: HTTP/HTTPS connections, TLS termination
2. **Middleware Pipeline**: Request processing chain (logging, auth, rate limiting)
3. **Core Components**: Authentication, authorization, rate limiting, routing
4. **Observability**: Metrics, health checks, logging

### Key Design Principles
- **Asynchronous I/O**: Use Tokio runtime for high concurrency
- **Stateless Design**: No local session state, externalize to Redis/database
- **Fail-Safe**: Configure fail-open vs fail-closed for dependencies
- **Structured Logging**: JSON logs with correlation IDs
- **Security First**: TLS, token validation, minimal sensitive data logging

### Middleware Execution Order
1. Request logging (entry)
2. Correlation ID injection
3. Authentication
4. Authorization
5. Rate limiting
6. Request forwarding
7. Response logging

## Testing Guidelines

### Unit Tests
- Test individual components in isolation
- Mock external dependencies
- Use property-based testing for complex logic
- Aim for >80% code coverage

### Integration Tests
- Test end-to-end request flows
- Test error scenarios
- Test middleware chain execution
- Verify logging and metrics

### Performance Testing
- Load test to validate throughput targets (>10,000 req/sec)
- Verify latency targets (gateway overhead <10ms)
- Test under various loads and conditions

## Performance Considerations

### Target Metrics
- **Throughput**: >10,000 requests/second per instance
- **Latency**: <10ms gateway overhead
- **Resource Usage**: Efficient memory and CPU utilization

### Optimization Tips
- Use connection pooling for upstream services
- Implement caching for session data (short TTL)
- Asynchronous logging to avoid blocking
- Pipeline Redis operations when possible

## Security Best Practices

### Token Handling
- Never log full token values
- Transmit tokens only over TLS
- Use HttpOnly, Secure, SameSite cookie flags
- Implement token expiration and revocation

### Sensitive Data
- Redact passwords, tokens, PII in logs
- Sanitize error messages for clients
- Use environment variables for secrets
- Never commit secrets to version control

### Input Validation
- Validate all incoming requests
- Enforce request size limits
- Implement rate limiting
- Protect against common attacks (XSS, CSRF, injection)

## Observability

### Metrics
- Expose Prometheus-compatible metrics at `/metrics`
- Track request latency, error rates, throughput
- Monitor authentication and rate limiting events
- Track upstream service health

### Logging
- Use structured JSON logs
- Include correlation IDs in all logs
- Log at appropriate levels (ERROR, WARN, INFO, DEBUG, TRACE)
- Configure log sinks (stdout, file, remote)

### Health Checks
- `/health/live`: Liveness check (process running)
- `/health/ready`: Readiness check (dependencies available)

## Configuration

### Configuration Sources (in precedence order)
1. Command-line arguments
2. Environment variables (prefixed with `GATEWAY_`)
3. Configuration file (YAML/TOML)
4. Default values

### Hot-Reload Support
- Log level changes
- Rate limit adjustments
- Route additions/removals
- Trigger via SIGHUP or admin API

## Additional Resources

- **Design Document**: `API_GATEWAY_DESIGN.md` - Complete architecture specification
- **Rust Book**: https://doc.rust-lang.org/book/ - Learn Rust
- **Tokio Documentation**: https://tokio.rs/tokio/tutorial - Async runtime
- **Cargo Book**: https://doc.rust-lang.org/cargo/ - Build tool and package manager

## Quick Reference

### Essential Commands
```bash
# Development
cargo build                    # Build debug version
cargo build --release          # Build release version
cargo test                     # Run tests
cargo test -- --nocapture      # Run tests with output
cargo bench                    # Run benchmarks

# Code Quality
cargo fmt --all                # Format code
cargo clippy --all-targets --all-features -- -D warnings  # Lint
cargo audit                    # Security audit

# Documentation
cargo doc --open               # Generate and open docs

# Cleaning
cargo clean                    # Remove build artifacts
```

### Pre-Commit Checklist
- [ ] Code is formatted (`cargo fmt --all`)
- [ ] No clippy warnings (`cargo clippy --all-targets --all-features -- -D warnings`)
- [ ] All tests pass (`cargo test --verbose`)
- [ ] Project builds (`cargo build --verbose`)
- [ ] No security vulnerabilities (`cargo audit`)
- [ ] Commit message is clear and descriptive

## Getting Help

If you encounter issues:
1. Check the error message carefully
2. Review relevant sections in `API_GATEWAY_DESIGN.md`
3. Search for similar issues in Rust documentation
4. Check the project's issue tracker
5. Ask for clarification from the team
