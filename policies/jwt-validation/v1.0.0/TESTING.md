# JWT Validation Policy - Testing Strategy

This document outlines the comprehensive testing strategy for the JWT validation policy.

## Table of Contents

1. [Unit Tests](#unit-tests)
2. [Integration Tests](#integration-tests)
3. [Manual Testing](#manual-testing)
4. [Performance Testing](#performance-testing)
5. [Security Testing](#security-testing)

## Unit Tests

Unit tests are located in `jwt-validation_test.go` and cover all core functionality.

### Running Unit Tests

```bash
cd policies/jwt-validation/v1.0.0
go test -v
```

### Test Coverage

```bash
go test -cover
go test -coverprofile=coverage.out
go tool cover -html=coverage.out
```

### Test Categories

#### 1. Configuration Validation (Tests 1-4)
- ✅ Policy name verification
- ✅ Valid configuration acceptance
- ✅ Missing token extraction method rejection
- ✅ Missing verification method rejection

#### 2. Token Extraction (Tests 5-8)
- ✅ Extract from Authorization header with Bearer prefix
- ✅ Extract from query parameters
- ✅ Extract from cookies
- ✅ Handle missing token scenarios

#### 3. Claims Validation (Tests 9-13)
- ✅ Valid issuer verification
- ✅ Invalid issuer rejection
- ✅ Expired token rejection
- ✅ Not-yet-valid token (nbf) rejection
- ✅ Clock skew tolerance

#### 4. Audience Validation (Tests 14-16)
- ✅ String audience format
- ✅ Array audience format
- ✅ Audience mismatch rejection

#### 5. Scope Validation (Tests 17-21)
- ✅ Required scopes (all must be present)
- ✅ Missing required scope rejection
- ✅ Optional scopes (at least one)
- ✅ No optional scopes present rejection
- ✅ Array format scope handling

#### 6. Metadata Mapping (Tests 22-24)
- ✅ Include list filtering
- ✅ Exclude list filtering
- ✅ Custom prefix support

#### 7. Error Handling (Tests 25-26)
- ✅ Mandatory mode (401 response)
- ✅ Non-mandatory mode (pass-through)

#### 8. JWKS Functionality (Tests 27-28)
- ✅ JWK to RSA public key conversion
- ✅ JWKS server integration with mock server

#### 9. Helper Functions (Tests 29-30)
- ✅ Algorithm validation
- ✅ Clock skew calculation

## Integration Tests

### End-to-End Test with Real JWT

Create a file `integration_test.go`:

```go
package jwtvalidation_test

import (
    "testing"
    "time"
    
    "github.com/envoy-policy-engine/policies/jwt-validation"
    "github.com/envoy-policy-engine/sdk/policies"
    "github.com/golang-jwt/jwt/v5"
)

func TestJWTValidationPolicy_EndToEnd_Success(t *testing.T) {
    // 1. Create policy instance
    policy := jwtvalidation.NewPolicy()
    
    // 2. Configure policy
    config := map[string]interface{}{
        "header": "Authorization",
        "prefix": "Bearer ",
        "publicKey": `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----`,
        "issuer": "https://auth.example.com",
        "audience": []interface{}{"api.example.com"},
        "validateExpiry": true,
        "mandatory": true,
    }
    
    // 3. Validate configuration
    if err := policy.Validate(config); err != nil {
        t.Fatalf("Config validation failed: %v", err)
    }
    
    // 4. Create request context with valid JWT
    ctx := &policies.RequestContext{
        Headers: map[string][]string{
            "authorization": {"Bearer <valid-jwt-token>"},
        },
        Metadata: make(map[string]interface{}),
    }
    
    // 5. Execute policy
    action := policy.(policies.RequestPolicy).ExecuteRequest(ctx, config)
    
    // 6. Verify success
    if _, ok := action.Action.(policies.ImmediateResponse); ok {
        t.Fatal("Expected request to pass, but got immediate response")
    }
    
    // 7. Verify metadata was set
    if ctx.Metadata["authenticated"] != true {
        t.Error("Expected authenticated metadata to be true")
    }
}
```

## Manual Testing

### Prerequisites

1. **Generate RSA Key Pair**

```bash
# Generate private key
openssl genrsa -out private.pem 2048

# Extract public key
openssl rsa -in private.pem -pubout -out public.pem
```

2. **Create Test JWT Token**

Use [jwt.io](https://jwt.io) or create programmatically:

```go
package main

import (
    "crypto/rsa"
    "crypto/x509"
    "encoding/pem"
    "fmt"
    "os"
    "time"
    
    "github.com/golang-jwt/jwt/v5"
)

func main() {
    // Load private key
    keyData, _ := os.ReadFile("private.pem")
    block, _ := pem.Decode(keyData)
    privateKey, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
    
    // Create claims
    claims := jwt.MapClaims{
        "iss": "https://auth.example.com",
        "aud": "api.example.com",
        "sub": "user123",
        "exp": time.Now().Add(1 * time.Hour).Unix(),
        "iat": time.Now().Unix(),
        "email": "user@example.com",
        "role": "admin",
        "scope": "read:users write:users",
    }
    
    // Generate token
    token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
    tokenString, _ := token.SignedString(privateKey)
    
    fmt.Println("JWT Token:")
    fmt.Println(tokenString)
}
```

### Test Scenarios

#### Scenario 1: Valid Token with All Claims

**Config:**
```yaml
header: "Authorization"
prefix: "Bearer "
publicKey: "<public-key-pem>"
issuer: "https://auth.example.com"
audience: ["api.example.com"]
requiredScopes: ["read:users"]
validateExpiry: true
mandatory: true
mapClaimsToMetadata:
  enabled: true
  prefix: "jwt."
  include: ["sub", "email", "role"]
```

**Expected Result:**
- ✅ Request passes
- ✅ `authenticated` metadata = true
- ✅ Claims mapped to metadata

#### Scenario 2: Expired Token

**Config:** Same as Scenario 1

**Token:** Token with `exp` in the past

**Expected Result:**
- ❌ 401 Unauthorized
- ❌ Error: "token expired"

#### Scenario 3: Invalid Issuer

**Config:** Issuer = "https://auth.example.com"

**Token:** Token with `iss` = "https://wrong-issuer.com"

**Expected Result:**
- ❌ 401 Unauthorized
- ❌ Error: "invalid issuer"

#### Scenario 4: Missing Required Scope

**Config:** Required scopes = ["read:users", "write:users"]

**Token:** Token with `scope` = "read:users" only

**Expected Result:**
- ❌ 401 Unauthorized
- ❌ Error: "missing required scope: write:users"

#### Scenario 5: Non-Mandatory Mode (Token Missing)

**Config:**
```yaml
header: "Authorization"
publicKey: "<public-key-pem>"
mandatory: false
```

**Request:** No Authorization header

**Expected Result:**
- ✅ Request passes
- ❌ `authenticated` metadata not set
- ✅ Continues to next policy

#### Scenario 6: JWKS URL Validation

**Config:**
```yaml
header: "Authorization"
prefix: "Bearer "
jwksUrl: "https://auth.example.com/.well-known/jwks.json"
jwksRefreshInterval: "5m"
issuer: "https://auth.example.com"
```

**Setup JWKS Server:**
```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "key-1",
      "n": "<base64url-encoded-modulus>",
      "e": "AQAB",
      "alg": "RS256"
    }
  ]
}
```

**Expected Result:**
- ✅ Fetches keys from JWKS URL
- ✅ Caches keys
- ✅ Validates token using correct key

## Performance Testing

### Load Test Configuration

```bash
# Install hey (HTTP load testing tool)
go install github.com/rakyll/hey@latest

# Test with valid tokens
hey -n 10000 -c 100 -H "Authorization: Bearer <token>" \
  http://localhost:8080/api/resource
```

### Performance Benchmarks

Create `jwt-validation_bench_test.go`:

```go
package jwtvalidation

import (
    "testing"
    
    "github.com/envoy-policy-engine/sdk/policies"
)

func BenchmarkTokenExtraction(b *testing.B) {
    policy := &JWTValidationPolicy{}
    ctx := &policies.RequestContext{
        Headers: map[string][]string{
            "authorization": {"Bearer test-token-123"},
        },
    }
    config := map[string]interface{}{
        "header": "Authorization",
        "prefix": "Bearer ",
    }
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        policy.extractToken(ctx, config)
    }
}

func BenchmarkClaimsValidation(b *testing.B) {
    policy := &JWTValidationPolicy{}
    claims := jwt.MapClaims{
        "iss": "https://auth.example.com",
        "aud": "api.example.com",
        "sub": "user123",
        "exp": float64(time.Now().Add(1 * time.Hour).Unix()),
    }
    config := map[string]interface{}{
        "issuer": "https://auth.example.com",
        "audience": []interface{}{"api.example.com"},
    }
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        policy.validateClaims(claims, config)
    }
}
```

Run benchmarks:
```bash
go test -bench=. -benchmem
```

## Security Testing

### Test Cases

#### 1. Algorithm Confusion Attack

**Test:** Token signed with HS256 but header claims RS256

**Expected:** Rejection due to algorithm mismatch

#### 2. None Algorithm Attack

**Test:** Token with `alg: none`

**Expected:** Rejection (none not in allowed algorithms)

#### 3. Key Confusion

**Test:** Token signed with different key but same kid

**Expected:** Signature verification failure

#### 4. Token Reuse

**Test:** Use same token multiple times

**Expected:** Should work (unless using jti claim tracking)

#### 5. Injection in Claims

**Test:** JWT with malicious claims values
```json
{
  "sub": "user123'; DROP TABLE users; --",
  "email": "<script>alert('xss')</script>"
}
```

**Expected:** Claims stored as-is but properly escaped when used

#### 6. JWKS URL Manipulation

**Test:** JWKS URL points to attacker-controlled server

**Expected:** Only HTTPS URLs should be allowed (add validation)

## Continuous Integration

### GitHub Actions Workflow

Create `.github/workflows/jwt-policy-test.yml`:

```yaml
name: JWT Policy Tests

on:
  push:
    paths:
      - 'policies/jwt-validation/**'
  pull_request:
    paths:
      - 'policies/jwt-validation/**'

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.23'
      
      - name: Run tests
        working-directory: policies/jwt-validation/v1.0.0
        run: |
          go test -v -race -coverprofile=coverage.out
          go tool cover -func=coverage.out
      
      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          files: ./policies/jwt-validation/v1.0.0/coverage.out
```

## Test Data

### Valid Token Examples

Save to `testdata/valid-token.txt`:
```
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2V5LTEifQ...
```

### Invalid Token Examples

Save to `testdata/expired-token.txt`, `testdata/invalid-signature.txt`, etc.

## Debugging

### Enable Verbose Logging

```go
// In tests, print detailed information
t.Logf("Token: %s", token)
t.Logf("Claims: %+v", claims)
t.Logf("Metadata: %+v", ctx.Metadata)
```

### Inspect JWT Tokens

```bash
# Decode JWT (without verification)
echo "<token>" | jq -R 'split(".") | .[1] | @base64d | fromjson'
```

## Success Criteria

- [ ] All unit tests pass (30/30)
- [ ] Code coverage > 80%
- [ ] Integration tests pass
- [ ] Performance benchmarks meet targets
- [ ] Security tests pass
- [ ] Manual test scenarios verified
- [ ] CI/CD pipeline green

## Next Steps

1. Run unit tests: `go test -v`
2. Check coverage: `go test -cover`
3. Run benchmarks: `go test -bench=.`
4. Perform manual testing with real tokens
5. Security audit with penetration testing
6. Load testing in staging environment
