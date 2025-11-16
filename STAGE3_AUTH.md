# Stage 3: Authentication and Authorization

This document describes the authentication and authorization features implemented in Stage 3 of the API Gateway.

## Overview

Stage 3 implements:
- **JWT Token Authentication**: Validates session tokens using JWT (HS256, RS256, ES256 algorithms)
- **Role-Based Access Control (RBAC)**: Controls access based on user roles
- **Permission-Based Access Control (PBAC)**: Controls access based on specific permissions
- **Token Extraction**: Extracts tokens from both cookies and Authorization headers
- **Comprehensive Error Handling**: Proper HTTP status codes and error messages for auth failures

## Configuration

### Authentication Configuration

Add the `auth` section to your configuration:

```json
{
  "auth": {
    "jwt_secret": "your-secret-key",
    "jwt_algorithm": "HS256",
    "cookie_name": "session_token",
    "jwt_issuer": "https://auth.example.com",
    "jwt_audience": "api-gateway"
  }
}
```

**Configuration Fields:**
- `jwt_secret`: Secret key for HS256 algorithm (required for HS256)
- `jwt_public_key`: Public key for RS256/ES256 algorithms (required for RS256/ES256)
- `jwt_algorithm`: JWT algorithm (HS256, RS256, or ES256) - default: HS256
- `cookie_name`: Name of the session cookie - default: session_token
- `jwt_issuer`: Expected issuer (iss claim) - optional
- `jwt_audience`: Expected audience (aud claim) - optional

**Environment Variables:**
You can also configure authentication using environment variables:
- `GATEWAY_JWT_SECRET`: JWT secret key
- `GATEWAY_JWT_ALGORITHM`: JWT algorithm
- `GATEWAY_COOKIE_NAME`: Cookie name
- `GATEWAY_JWT_ISSUER`: JWT issuer
- `GATEWAY_JWT_AUDIENCE`: JWT audience

### Route Configuration

Configure authentication and authorization requirements per route:

```json
{
  "routes": [
    {
      "id": "public-route",
      "methods": ["GET"],
      "path": "/api/public",
      "upstream_id": "service",
      "auth_required": false
    },
    {
      "id": "authenticated-route",
      "methods": ["GET"],
      "path": "/api/users",
      "upstream_id": "user-service",
      "auth_required": true,
      "required_permissions": ["users:read"]
    },
    {
      "id": "admin-only-route",
      "methods": ["POST"],
      "path": "/api/users",
      "upstream_id": "user-service",
      "auth_required": true,
      "required_roles": ["admin"],
      "required_permissions": ["users:write"]
    }
  ]
}
```

**Route Auth Fields:**
- `auth_required`: Boolean indicating if authentication is required (default: false)
- `required_roles`: Array of roles (RBAC) - user must have at least ONE of these roles
- `required_permissions`: Array of permissions (PBAC) - user must have ALL of these permissions

## JWT Token Format

The gateway expects JWT tokens with the following claims:

**Standard Claims:**
- `sub` (subject): User ID (required)
- `exp` (expiration): Expiration timestamp (required)
- `iss` (issuer): Token issuer (validated if configured)
- `aud` (audience): Token audience (validated if configured)
- `iat` (issued at): Issued timestamp (optional)
- `nbf` (not before): Not before timestamp (optional)

**Custom Claims:**
- `username`: Username (optional)
- `roles`: Array of role strings (optional)
- `permissions`: Array of permission strings (optional)

**Example JWT Payload:**
```json
{
  "sub": "user123",
  "username": "john.doe",
  "roles": ["admin", "user"],
  "permissions": ["users:read", "users:write", "orders:read"],
  "exp": 1234567890,
  "iat": 1234564290,
  "iss": "https://auth.example.com",
  "aud": "api-gateway"
}
```

## Token Submission

Clients can submit tokens in two ways:

### 1. Cookie (Recommended)
```http
GET /api/users HTTP/1.1
Host: gateway.example.com
Cookie: session_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### 2. Authorization Header
```http
GET /api/users HTTP/1.1
Host: gateway.example.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

## Authentication Flow

1. **Token Extraction**: Gateway extracts token from cookie or Authorization header
2. **Token Validation**:
   - Validates token signature
   - Checks expiration (`exp` claim)
   - Validates issuer if configured (`iss` claim)
   - Validates audience if configured (`aud` claim)
3. **Identity Resolution**: Extracts user ID, roles, and permissions from token claims
4. **Authorization Check** (if configured):
   - **RBAC**: Checks if user has at least one of the required roles
   - **PBAC**: Checks if user has all required permissions
5. **Request Forwarding**: If auth succeeds, forwards request to upstream service

## Error Responses

### 401 Unauthorized - Authentication Failures

**Missing Token:**
```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="api-gateway"
Content-Type: application/json

{
  "error": {
    "code": "missing_token",
    "message": "Authentication token is required",
    "correlation_id": "abc-123",
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

**Invalid Token:**
```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="api-gateway"
Content-Type: application/json

{
  "error": {
    "code": "invalid_token",
    "message": "Invalid signature",
    "correlation_id": "abc-123",
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

**Expired Token:**
```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="api-gateway"
Content-Type: application/json

{
  "error": {
    "code": "token_expired",
    "message": "Authentication token has expired. Please refresh your token.",
    "correlation_id": "abc-123",
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

### 403 Forbidden - Authorization Failures

**Insufficient Permissions:**
```http
HTTP/1.1 403 Forbidden
Content-Type: application/json

{
  "error": {
    "code": "insufficient_permissions",
    "message": "You do not have permission to access this resource",
    "correlation_id": "abc-123",
    "timestamp": "2024-01-15T10:30:00Z",
    "details": {
      "required_roles": ["admin"],
      "user_roles": ["user"]
    }
  }
}
```

## Logging

Authentication and authorization events are logged with structured logging:

**Authentication Success:**
```
INFO Authentication successful correlation_id=abc-123 user_id=user123 roles=["admin", "user"]
```

**Authentication Failure:**
```
WARN Authentication failed: token validation error correlation_id=abc-123 error="Invalid signature"
```

**Authorization Failure:**
```
WARN Authorization failed: insufficient roles correlation_id=abc-123 user_id=user123 user_roles=["user"] required_roles=["admin"]
```

## Security Considerations

1. **TLS Required**: Always use HTTPS in production to protect tokens in transit
2. **Token Expiration**: Use short-lived tokens (15-60 minutes recommended)
3. **Cookie Security**: Session cookies should have:
   - `HttpOnly` flag (prevents JavaScript access)
   - `Secure` flag (HTTPS only)
   - `SameSite=Strict` or `SameSite=Lax` (CSRF protection)
4. **Secret Management**: Never hardcode secrets in configuration files
   - Use environment variables for JWT secrets
   - Rotate secrets regularly
5. **Algorithm Selection**:
   - Use HS256 for simple deployments (symmetric key)
   - Use RS256 for distributed systems (asymmetric keys)
   - Never use algorithm "none"

## Testing

The gateway includes comprehensive tests for authentication:

```bash
cargo test --test auth_test
```

Tests cover:
- Valid token validation
- Expired token rejection
- Invalid signature rejection
- Issuer and audience validation
- Role and permission checks

## Example: Generating a Test Token

```bash
# Using a JWT library or online tool, create a token with:
# - Algorithm: HS256
# - Secret: your-secret-key
# - Payload:
{
  "sub": "user123",
  "username": "testuser",
  "roles": ["admin", "user"],
  "permissions": ["users:read", "users:write"],
  "exp": 1735689600,
  "iat": 1735686000
}
```

## Future Enhancements

Planned for future stages:
- Token revocation support (revocation cache)
- Redis-based session store for opaque tokens
- OAuth2 integration with external authorization servers
- Rate limiting per user
- Audit logging for security events
- Support for API keys (in addition to JWT)

## Related Documentation

- [API Gateway Design Specification](./API_GATEWAY_DESIGN.md) - Full design document
- [Configuration Example](./config.example.json) - Example configuration file
