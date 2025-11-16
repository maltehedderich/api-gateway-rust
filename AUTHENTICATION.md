# Authentication and Authorization

This document describes how to configure and use the session token authentication and authorization features in the API Gateway.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Authentication Flow](#authentication-flow)
- [Configuration](#configuration)
- [JWT Token Format](#jwt-token-format)
- [Route-Level Security](#route-level-security)
- [Error Responses](#error-responses)
- [Metrics](#metrics)
- [Examples](#examples)

## Overview

The API Gateway implements **Stage 4: Session Token Authentication** as specified in the design document. It supports OAuth2-based session authentication using JWT (JSON Web Tokens) to secure routes and enforce role-based and permission-based access control.

### Key Features

- ✅ **JWT Token Validation**: Supports HS256 (symmetric), RS256, and ES256 (asymmetric) algorithms
- ✅ **Dual Token Sources**: Extracts tokens from cookies or Authorization headers
- ✅ **Claims Validation**: Validates `exp`, `nbf`, `iss`, and `aud` claims
- ✅ **Role-Based Access Control (RBAC)**: Restrict routes based on user roles
- ✅ **Permission-Based Access Control (PBAC)**: Enforce fine-grained permissions
- ✅ **Comprehensive Logging**: All authentication events are logged with correlation IDs
- ✅ **Prometheus Metrics**: Authentication and authorization metrics for monitoring
- ✅ **Per-Route Configuration**: Flexible authentication requirements per route

## Authentication Flow

### Request Processing

1. **Route Matching**: Gateway matches the incoming request to a configured route
2. **Token Extraction** (if auth required):
   - Checks for session token in Cookie header (`session_token` by default)
   - Falls back to Authorization header (Bearer token)
3. **Token Validation**:
   - Parses JWT structure
   - Verifies signature using configured secret or public key
   - Validates claims (expiration, issuer, audience)
4. **Identity Resolution**: Extracts user context (user_id, roles, permissions) from token
5. **Authorization Check** (if required):
   - RBAC: Checks if user has required roles
   - PBAC: Checks if user has all required permissions
6. **Request Forwarding**: Forwards request to upstream service if authorized
7. **Metrics Recording**: Records authentication and authorization metrics

### Error Handling

Authentication failures result in `401 Unauthorized` responses:
- Missing token: `missing_token`
- Invalid signature: `invalid_token`
- Expired token: `token_expired`
- Revoked token: `token_revoked`

Authorization failures result in `403 Forbidden` responses:
- Insufficient roles: `insufficient_permissions`
- Missing permissions: `insufficient_permissions`

All errors include:
- Correlation ID for tracing
- Structured error response
- `WWW-Authenticate` header (for 401 responses)

## Configuration

### Environment Variables

**For production, always use environment variables for secrets:**

```bash
# JWT secret for HS256 algorithm
export GATEWAY_JWT_SECRET="your-secret-key-min-256-bits"

# JWT algorithm (HS256, RS256, or ES256)
export GATEWAY_JWT_ALGORITHM="HS256"

# Cookie name (optional, default: session_token)
export GATEWAY_COOKIE_NAME="session_token"

# JWT issuer validation (optional)
export GATEWAY_JWT_ISSUER="https://auth.example.com"

# JWT audience validation (optional)
export GATEWAY_JWT_AUDIENCE="api-gateway"
```

### Configuration File

Add authentication configuration to your `config.yaml`:

```yaml
auth:
  # JWT algorithm for token validation
  jwt_algorithm: "HS256"  # or "RS256", "ES256"

  # For HS256 (symmetric key)
  jwt_secret: "your-secret-key"  # Use environment variable in production

  # For RS256/ES256 (asymmetric keys)
  # jwt_public_key: |
  #   -----BEGIN PUBLIC KEY-----
  #   ...
  #   -----END PUBLIC KEY-----

  # Cookie name for session token
  cookie_name: "session_token"

  # Optional: JWT issuer claim validation
  jwt_issuer: "https://auth.example.com"

  # Optional: JWT audience claim validation
  jwt_audience: "api-gateway"
```

## JWT Token Format

### Token Structure

The gateway expects JWT tokens with the following claims:

```json
{
  "sub": "user123",              // Required: Subject (user ID)
  "username": "john_doe",        // Optional: Human-readable username
  "roles": ["admin", "user"],    // Optional: User roles for RBAC
  "permissions": [               // Optional: User permissions for PBAC
    "users:read",
    "users:write"
  ],
  "exp": 1234567890,            // Required: Expiration timestamp (Unix)
  "nbf": 1234567800,            // Optional: Not before timestamp
  "iat": 1234567800,            // Optional: Issued at timestamp
  "iss": "https://auth.example.com",  // Optional: Issuer
  "aud": "api-gateway",         // Optional: Audience
  "jti": "unique-token-id"      // Optional: JWT ID
}
```

### Supported Algorithms

1. **HS256 (HMAC with SHA-256)**
   - Symmetric key algorithm
   - Requires shared secret between gateway and auth server
   - Fast and simple
   - Use `jwt_secret` configuration

2. **RS256 (RSA with SHA-256)**
   - Asymmetric key algorithm
   - Auth server signs with private key
   - Gateway validates with public key
   - Use `jwt_public_key` configuration

3. **ES256 (ECDSA with SHA-256)**
   - Asymmetric key algorithm (elliptic curve)
   - Smaller key sizes than RSA
   - Use `jwt_public_key` configuration

## Route-Level Security

### Public Routes

Routes without `auth_required` are public:

```yaml
routes:
  - id: "public-api"
    methods: ["GET"]
    path: "/api/public/*"
    upstream_id: "service"
    # No auth_required - public route
```

### Protected Routes (Authentication Only)

Require valid JWT token but no specific roles/permissions:

```yaml
routes:
  - id: "protected-api"
    methods: ["GET"]
    path: "/api/user/profile"
    upstream_id: "user-service"
    auth_required: true
    # Any authenticated user can access
```

### Role-Based Access Control (RBAC)

Require user to have at least one of the specified roles:

```yaml
routes:
  - id: "admin-api"
    methods: ["GET", "POST", "PUT", "DELETE"]
    path: "/api/admin/*"
    upstream_id: "admin-service"
    auth_required: true
    required_roles: ["admin", "superuser"]
    # User must have 'admin' OR 'superuser' role
```

### Permission-Based Access Control (PBAC)

Require user to have ALL specified permissions:

```yaml
routes:
  - id: "create-order"
    methods: ["POST"]
    path: "/api/orders"
    upstream_id: "order-service"
    auth_required: true
    required_permissions: ["orders:create"]
    # User must have 'orders:create' permission
```

### Combined RBAC and PBAC

You can combine both role and permission checks:

```yaml
routes:
  - id: "sensitive-operation"
    methods: ["DELETE"]
    path: "/api/data/{id}"
    upstream_id: "data-service"
    auth_required: true
    required_roles: ["admin"]
    required_permissions: ["data:delete"]
    # User must have 'admin' role AND 'data:delete' permission
```

## Error Responses

### 401 Unauthorized - Missing Token

```json
{
  "error": {
    "code": "missing_token",
    "message": "Authentication token is required",
    "correlation_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "timestamp": "2024-03-15T12:34:56Z"
  }
}
```

Headers:
```
WWW-Authenticate: Bearer realm="api-gateway"
```

### 401 Unauthorized - Expired Token

```json
{
  "error": {
    "code": "token_expired",
    "message": "Authentication token has expired. Please refresh your token.",
    "correlation_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "timestamp": "2024-03-15T12:34:56Z"
  }
}
```

### 403 Forbidden - Insufficient Permissions

```json
{
  "error": {
    "code": "insufficient_permissions",
    "message": "You do not have permission to access this resource",
    "correlation_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "timestamp": "2024-03-15T12:34:56Z",
    "details": {
      "required_roles": ["admin"],
      "user_roles": ["user"]
    }
  }
}
```

## Metrics

The gateway exposes Prometheus-compatible metrics at `/metrics`:

### Authentication Metrics

- **`auth_attempts_total{result="success|failure|error"}`**
  - Counter of authentication attempts by result
  - Labels: `result` (success, failure, error)

- **`auth_failures_total{reason="..."}`**
  - Counter of authentication failures by reason
  - Labels: `reason` (missing_token, invalid_token, token_expired, token_revoked, validation_error)

- **`auth_duration_seconds{operation="validate_token"}`**
  - Histogram of authentication operation duration
  - Labels: `operation`

### Authorization Metrics

- **`authz_decisions_total{decision="allowed|denied"}`**
  - Counter of authorization decisions
  - Labels: `decision` (allowed, denied)

- **`authz_duration_seconds{operation="..."}`**
  - Histogram of authorization operation duration
  - Labels: `operation` (check_roles, check_permissions, check_success)

### Example Metrics Query

Monitor authentication failure rate:
```promql
rate(auth_failures_total[5m])
```

Monitor authorization denial rate:
```promql
rate(authz_decisions_total{decision="denied"}[5m])
```

## Examples

### Example 1: Generate HS256 Token (Python)

```python
import jwt
import time

secret = "your-secret-key-min-256-bits"

payload = {
    "sub": "user123",
    "username": "john_doe",
    "roles": ["admin", "user"],
    "permissions": ["users:read", "users:write"],
    "exp": int(time.time()) + 3600,  # Expires in 1 hour
    "iat": int(time.time()),
    "iss": "https://auth.example.com",
    "aud": "api-gateway"
}

token = jwt.encode(payload, secret, algorithm="HS256")
print(token)
```

### Example 2: Making Authenticated Request (curl)

Using Cookie:
```bash
curl -H "Cookie: session_token=<jwt-token>" \
     https://gateway.example.com/api/admin/users
```

Using Authorization Header:
```bash
curl -H "Authorization: Bearer <jwt-token>" \
     https://gateway.example.com/api/admin/users
```

### Example 3: Testing with Different Roles

```bash
# Admin user (should succeed)
curl -H "Authorization: Bearer <admin-token>" \
     https://gateway.example.com/api/admin/users

# Regular user (should fail with 403)
curl -H "Authorization: Bearer <user-token>" \
     https://gateway.example.com/api/admin/users
```

### Example 4: Monitoring Authentication

```bash
# View all metrics
curl http://gateway.example.com/metrics

# Filter authentication metrics
curl http://gateway.example.com/metrics | grep auth_
```

## Security Best Practices

1. **Use Environment Variables for Secrets**
   - Never commit JWT secrets to version control
   - Load secrets from environment variables or secret managers

2. **Use Strong Secrets**
   - HS256: Minimum 256-bit (32-character) secret
   - RS256/ES256: Use 2048-bit or larger keys

3. **Set Token Expiration**
   - Use short-lived tokens (15-60 minutes)
   - Implement token refresh flows in your auth server

4. **Enable TLS**
   - Always use HTTPS in production
   - Never transmit tokens over plain HTTP

5. **Validate Issuer and Audience**
   - Configure `jwt_issuer` and `jwt_audience` to prevent token reuse from other services

6. **Use HttpOnly Cookies**
   - When using cookies, ensure they have HttpOnly, Secure, and SameSite flags set
   - Set these flags in your auth server when issuing tokens

7. **Monitor Metrics**
   - Set up alerts for high authentication failure rates
   - Monitor authorization denial patterns

8. **Implement Rate Limiting**
   - Use rate limiting (Stage 5) to prevent brute force attacks
   - Limit authentication attempts per IP/user

## Troubleshooting

### Problem: "Authentication token is required"

**Solution**: Ensure you're sending the token in either:
- Cookie header: `Cookie: session_token=<token>`
- Authorization header: `Authorization: Bearer <token>`

### Problem: "Token expired"

**Solution**: The token has passed its `exp` (expiration) time. Request a new token from your auth server.

### Problem: "Invalid signature"

**Solution**:
- Verify the JWT secret/public key matches between auth server and gateway
- Check that the algorithm matches (HS256, RS256, ES256)
- Ensure the token hasn't been tampered with

### Problem: "Insufficient permissions"

**Solution**: The user's roles or permissions don't match the route requirements. Check:
- User token has correct roles/permissions
- Route configuration has correct `required_roles` or `required_permissions`

### Problem: "Invalid issuer" or "Invalid audience"

**Solution**: The token's `iss` or `aud` claims don't match the configured values. Either:
- Update the gateway configuration to match your auth server
- Ensure your auth server issues tokens with correct claims

## Related Documentation

- [API Gateway Design Specification](./API_GATEWAY_DESIGN.md) - Full design document
- [Configuration Guide](./config.example.yaml) - Complete configuration examples
- [Testing Guide](./tests/auth_test.rs) - Unit tests for authentication

## Support

For issues or questions:
- Check logs for correlation IDs and error details
- Review metrics at `/metrics` endpoint
- Examine authentication tests in `tests/auth_test.rs`
