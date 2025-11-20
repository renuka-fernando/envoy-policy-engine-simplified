# JWT Validation Policy

A comprehensive JWT (JSON Web Token) authentication and validation policy for the Envoy Policy Engine. This policy extracts, validates, and processes JWT tokens from incoming requests, providing secure authentication and authorization capabilities.

## Features

- **Flexible Token Extraction**: Extract JWT from headers, query parameters, or cookies
- **Multiple Verification Methods**: Support for JWKS URLs, inline public keys, and certificates
- **Comprehensive Validation**: Validates signature, expiration, issuer, audience, scopes, and custom claims
- **Claims Mapping**: Automatically maps JWT claims to request metadata for downstream policies
- **Scope-based Authorization**: Support for required and optional scope validation
- **Multi-tenancy Support**: Built-in tenant claim validation
- **Configurable Behavior**: Mandatory or optional authentication modes
- **Clock Skew Tolerance**: Handles time differences between systems

## Installation

The policy is automatically available when the Envoy Policy Engine is built with this policy included in the policy registry.

## Configuration

### Basic Example

```yaml
- name: jwtValidation
  version: v1.0.0
  executionCondition: "request.metadata[authenticated] != true"
  params:
    header: "Authorization"
    prefix: "Bearer "
    publicKey: |
      -----BEGIN PUBLIC KEY-----
      MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
      -----END PUBLIC KEY-----
    issuer: "https://auth.example.com"
    audience:
      - "api.example.com"
    validateExpiry: true
    mandatory: true
```

### Advanced Example with Scopes

```yaml
- name: jwtValidation
  version: v1.0.0
  params:
    # Token extraction
    header: "Authorization"
    prefix: "Bearer "
    
    # Signature verification
    jwksUrl: "https://auth.example.com/.well-known/jwks.json"
    jwksRefreshInterval: "5m"
    allowedAlgorithms:
      - RS256
      - ES256
    
    # Core claims validation
    issuer: "https://auth.example.com"
    audience:
      - "api.example.com"
      - "admin.example.com"
    tenant: "acme-corp"
    
    # Scope validation
    scopeClaim: "scope"
    requiredScopes:
      - "read:users"
      - "write:users"
    
    # Time validation
    validateExpiry: true
    validateNotBefore: true
    clockSkewSeconds: 300
    
    # Claim mapping
    mapClaimsToMetadata:
      enabled: true
      prefix: "jwt."
      include:
        - "sub"
        - "email"
        - "role"
        - "tenant"
    
    # Caching
    cache:
      enabled: true
      ttl: "5m"
    
    # Behavior
    mandatory: true
```

## Configuration Parameters

### Token Extraction

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `header` | string | No | `"Authorization"` | HTTP header to read JWT from |
| `prefix` | string | No | `"Bearer "` | Prefix to remove before decoding |
| `queryParam` | string | No | - | Query parameter name (alternative to header) |
| `cookieName` | string | No | - | Cookie name (alternative to header) |

### Signature & Key Material

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `jwksUrl` | string | No* | - | JWKS URL for public keys |
| `jwksRefreshInterval` | string | No | `"5m"` | JWKS cache refresh interval |
| `certificate` | string | No* | - | Inline PEM certificate |
| `publicKey` | string | No* | - | Inline PEM public key |
| `allowedAlgorithms` | array | No | `["RS256", "ES256"]` | Allowed signing algorithms |

*At least one verification method (`jwksUrl`, `certificate`, or `publicKey`) must be configured.

### Core JWT Claims Validation

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `issuer` | string | No | - | Expected `iss` claim value |
| `audience` | array | No | - | List of valid `aud` values |
| `subject` | string | No | - | Expected `sub` claim value |
| `tenant` | string | No | - | Expected tenant claim value |

### Scope / Permission Validation

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `scopeClaim` | string | No | `"scope"` | Claim name containing scopes |
| `requiredScopes` | array | No | - | All scopes must be present |
| `optionalScopes` | array | No | - | At least one must be present |

### Time Validations

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `validateExpiry` | boolean | No | `true` | Validate `exp` claim |
| `validateNotBefore` | boolean | No | `true` | Validate `nbf` claim |
| `clockSkewSeconds` | integer | No | `300` | Clock skew tolerance (seconds) |

### Claim Mapping

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `mapClaimsToMetadata.enabled` | boolean | No | `true` | Enable claim mapping |
| `mapClaimsToMetadata.prefix` | string | No | `"jwt."` | Metadata key prefix |
| `mapClaimsToMetadata.include` | array | No | All claims | Claims to include |
| `mapClaimsToMetadata.exclude` | array | No | - | Claims to exclude |

### Caching

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `cache.enabled` | boolean | No | `true` | Enable validation caching |
| `cache.ttl` | string | No | `"5m"` | Cache time-to-live |

### Failure Behavior

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `mandatory` | boolean | No | `true` | Reject request if token invalid |

## Behavior

### Success Flow

1. Extract JWT token from configured source (header/query/cookie)
2. Validate token signature using configured key material
3. Validate all configured claims (exp, nbf, iss, aud, scopes, etc.)
4. Map claims to request metadata with configured prefix
5. Set `request.metadata[authenticated] = true`
6. Continue to next policy in chain

### Failure Flow (Mandatory Mode)

1. Return 401 Unauthorized response immediately
2. Include `WWW-Authenticate: Bearer` header
3. Include JSON error message with details

### Failure Flow (Non-Mandatory Mode)

1. Do not set `authenticated` metadata flag
2. Continue to next policy in chain
3. Downstream policies can check authentication status

## Metadata

The policy sets the following metadata:

- `authenticated`: `true` if JWT validation succeeds
- `jwt.<claim>`: Each mapped claim with configured prefix (default: `jwt.`)

Example metadata after successful validation:

```
request.metadata[authenticated] = true
request.metadata[jwt.sub] = "user123"
request.metadata[jwt.email] = "user@example.com"
request.metadata[jwt.role] = "admin"
request.metadata[jwt.tenant] = "acme-corp"
```

## Error Responses

### 401 Unauthorized

Returned when authentication fails in mandatory mode:

```json
{
  "error": "unauthorized",
  "message": "token validation failed: token expired"
}
```

Common error messages:
- `"no token found"`
- `"token extraction failed: token not found in any configured source"`
- `"token validation failed: invalid signature"`
- `"token validation failed: token expired"`
- `"claims validation failed: invalid issuer"`
- `"claims validation failed: no matching audience found"`
- `"claims validation failed: missing required scope: read:users"`

## Use Cases

### API Gateway Authentication

```yaml
- name: jwtValidation
  version: v1.0.0
  params:
    header: "Authorization"
    prefix: "Bearer "
    jwksUrl: "https://auth.example.com/.well-known/jwks.json"
    issuer: "https://auth.example.com"
    audience: ["api.example.com"]
    mandatory: true
```

### Microservice Authorization

```yaml
- name: jwtValidation
  version: v1.0.0
  params:
    header: "X-Internal-Token"
    publicKey: "{{ .env.SERVICE_PUBLIC_KEY }}"
    requiredScopes:
      - "service:payment"
    mapClaimsToMetadata:
      enabled: true
      include: ["sub", "service_id"]
```

### Multi-Tenant SaaS

```yaml
- name: jwtValidation
  version: v1.0.0
  params:
    jwksUrl: "https://auth.saas.com/.well-known/jwks.json"
    issuer: "https://auth.saas.com"
    tenant: "{{ .request.path.tenant_id }}"
    mapClaimsToMetadata:
      enabled: true
      include: ["tenant", "organization_id", "role"]
```

## Supported Algorithms

- **HMAC**: HS256, HS384, HS512
- **RSA**: RS256, RS384, RS512
- **ECDSA**: ES256, ES384, ES512
- **RSA-PSS**: PS256, PS384, PS512

## Implementation Details

- Built on `github.com/golang-jwt/jwt/v5`
- Supports standard JWT claims (iss, aud, sub, exp, nbf, iat)
- Thread-safe claim validation
- Zero-copy metadata mapping where possible

## Security Considerations

1. **Algorithm Validation**: Always specify `allowedAlgorithms` to prevent algorithm confusion attacks
2. **Key Material**: Use JWKS URLs for production; rotate keys regularly
3. **Clock Skew**: Keep `clockSkewSeconds` minimal (default 5 minutes)
4. **Mandatory Mode**: Use `mandatory: true` for authenticated endpoints
5. **HTTPS Only**: JWKS URLs should always use HTTPS
6. **Token Caching**: Consider security vs performance tradeoff when enabling cache

## Testing

Generate a test JWT token:

```bash
# Using https://jwt.io or a JWT library
# Example payload:
{
  "iss": "https://auth.example.com",
  "aud": "api.example.com",
  "sub": "user123",
  "exp": 1735689600,
  "scope": "read:users write:users",
  "email": "user@example.com",
  "role": "admin"
}
```

Test request:

```bash
curl -H "Authorization: Bearer <your-jwt-token>" \
  http://localhost:8080/api/resource
```

## License

MIT
