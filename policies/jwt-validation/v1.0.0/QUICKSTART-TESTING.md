# JWT Validation Policy - Quick Test Guide

This guide helps you quickly test the JWT validation policy.

## Quick Start

### 1. Run Unit Tests

```bash
cd policies/jwt-validation/v1.0.0
go test -v
```

Expected output:
```
=== RUN   TestJWTValidationPolicy_Name
--- PASS: TestJWTValidationPolicy_Name (0.00s)
=== RUN   TestJWTValidationPolicy_Validate_ValidConfig
--- PASS: TestJWTValidationPolicy_Validate_ValidConfig (0.00s)
...
PASS
ok      github.com/envoy-policy-engine/policies/jwt-validation  0.XXXs
```

### 2. Run Integration Tests

```bash
go test -v -run Integration
```

### 3. Check Code Coverage

```bash
go test -cover
```

For detailed coverage report:
```bash
go test -coverprofile=coverage.out
go tool cover -html=coverage.out
```

### 4. Run Benchmarks

```bash
go test -bench=. -benchmem
```

## Generate Test Tokens

### Step 1: Generate RSA Key Pair

```bash
cd testdata
go run generate-token.go -generate-keys
```

This creates:
- `test-private.pem` - Private key (keep secret)
- `test-public.pem` - Public key (use in policy config)

### Step 2: Generate Valid Token

```bash
go run generate-token.go -key test-private.pem
```

Output:
```
=== JWT Token ===
eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2V5LTEiLCJ0eXAiOiJKV1QifQ...

=== Token Info ===
Issuer (iss): https://auth.test.com
Audience (aud): api.test.com
Subject (sub): user123
Email: user@test.com
Role: admin
Scopes: read:users write:users
Expiry: 1h0m0s from now
```

### Step 3: Test with cURL (Manual Testing)

```bash
# Copy the token from previous step
TOKEN="eyJhbGci..."

# Test against your service
curl -H "Authorization: Bearer $TOKEN" \
     http://localhost:8080/api/resource
```

## Test Scenarios

### Scenario 1: Valid Token ✅

```bash
go run generate-token.go -key test-private.pem \
  -iss https://auth.test.com \
  -aud api.test.com \
  -sub user123 \
  -role admin \
  -scopes "read:users write:users"
```

**Expected:** Request passes, authenticated = true

### Scenario 2: Expired Token ❌

```bash
go run generate-token.go -key test-private.pem -expired
```

**Expected:** 401 Unauthorized, error: "token expired"

### Scenario 3: Wrong Issuer ❌

```bash
go run generate-token.go -key test-private.pem \
  -iss https://wrong-issuer.com
```

**Expected:** 401 Unauthorized, error: "invalid issuer"

### Scenario 4: Missing Scope ❌

```bash
go run generate-token.go -key test-private.pem \
  -scopes "read:users"
```

With policy requiring both `read:users` and `write:users`:

**Expected:** 401 Unauthorized, error: "missing required scope"

### Scenario 5: Custom Expiry

```bash
# Token valid for 5 minutes
go run generate-token.go -key test-private.pem -exp 5m

# Token valid for 24 hours
go run generate-token.go -key test-private.pem -exp 24h
```

## Policy Configuration Examples

### Example 1: Basic Authentication

```yaml
params:
  header: "Authorization"
  prefix: "Bearer "
  publicKey: |
    -----BEGIN PUBLIC KEY-----
    <content of test-public.pem>
    -----END PUBLIC KEY-----
  validateExpiry: true
  mandatory: true
```

### Example 2: With Issuer & Audience

```yaml
params:
  header: "Authorization"
  prefix: "Bearer "
  publicKey: |
    -----BEGIN PUBLIC KEY-----
    ...
    -----END PUBLIC KEY-----
  issuer: "https://auth.test.com"
  audience:
    - "api.test.com"
  validateExpiry: true
  mandatory: true
```

### Example 3: With Scopes & Metadata Mapping

```yaml
params:
  header: "Authorization"
  prefix: "Bearer "
  publicKey: |
    -----BEGIN PUBLIC KEY-----
    ...
    -----END PUBLIC KEY-----
  issuer: "https://auth.test.com"
  requiredScopes:
    - "read:users"
    - "write:users"
  mapClaimsToMetadata:
    enabled: true
    prefix: "jwt."
    include:
      - "sub"
      - "email"
      - "role"
  mandatory: true
```

## Debugging Tests

### Run Specific Test

```bash
go test -v -run TestJWTValidationPolicy_ValidateClaims_ValidIssuer
```

### Run Tests with Race Detector

```bash
go test -race -v
```

### Enable Verbose Logging

In your test, add:
```go
t.Logf("Token: %s", token)
t.Logf("Claims: %+v", claims)
t.Logf("Config: %+v", config)
```

### Inspect JWT Token

```bash
# Decode JWT (shows header and payload)
echo "eyJhbGci..." | cut -d. -f2 | base64 -d 2>/dev/null | jq
```

Or use online tool: https://jwt.io

## Common Test Issues

### Issue 1: Import Errors

```
could not import github.com/golang-jwt/jwt/v5
```

**Solution:**
```bash
go mod tidy
```

### Issue 2: Key Format Errors

```
failed to decode PEM block
```

**Solution:** Ensure key is in PEM format:
```bash
# Check key format
head -1 test-private.pem
# Should show: -----BEGIN RSA PRIVATE KEY-----
```

### Issue 3: Token Expired During Test

**Solution:** Generate fresh token or increase expiry:
```bash
go run generate-token.go -exp 24h
```

## Test Checklist

Before submitting:

- [ ] All unit tests pass (`go test -v`)
- [ ] Integration tests pass (`go test -v -run Integration`)
- [ ] Code coverage > 80% (`go test -cover`)
- [ ] No race conditions (`go test -race`)
- [ ] Benchmarks run successfully (`go test -bench=.`)
- [ ] Manual testing with real tokens completed
- [ ] Documentation updated

## Quick Commands Reference

```bash
# Run all tests
go test -v

# Run with coverage
go test -v -cover

# Run integration tests only
go test -v -run Integration

# Run benchmarks
go test -bench=. -benchmem

# Generate test keys
cd testdata && go run generate-token.go -generate-keys

# Generate valid token
cd testdata && go run generate-token.go

# Generate expired token
cd testdata && go run generate-token.go -expired

# Run specific test
go test -v -run TestIntegration_ValidToken_Success

# Check for races
go test -race -v
```

## Next Steps

1. ✅ Run all tests: `go test -v`
2. ✅ Check coverage: `go test -cover`
3. ✅ Generate test keys
4. ✅ Test manually with curl
5. ✅ Review test results
6. ✅ Fix any failures
7. ✅ Document any issues

Happy Testing! 🎉
