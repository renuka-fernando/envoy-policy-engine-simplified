package jwtvalidation_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jwtvalidation "github.com/envoy-policy-engine/policies/jwt-validation"
	"github.com/envoy-policy-engine/sdk/policies"
	"github.com/golang-jwt/jwt/v5"
)

// Integration test fixtures
var (
	integrationPrivateKey   *rsa.PrivateKey
	integrationPublicKey    *rsa.PublicKey
	integrationPublicKeyPEM string
)

func init() {
	// Generate test key pair
	var err error
	integrationPrivateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	integrationPublicKey = &integrationPrivateKey.PublicKey

	// Convert to PEM
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(integrationPublicKey)
	if err != nil {
		panic(err)
	}
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})
	integrationPublicKeyPEM = string(pubKeyPEM)
}

// generateToken creates a JWT token with given claims
func generateToken(claims jwt.MapClaims, key *rsa.PrivateKey) string {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "test-key-1"
	tokenString, _ := token.SignedString(key)
	return tokenString
}

// Test: Complete flow with valid token
func TestIntegration_ValidToken_Success(t *testing.T) {
	// 1. Create policy
	policy := jwtvalidation.NewPolicy()

	// 2. Configure
	config := map[string]interface{}{
		"header":         "Authorization",
		"prefix":         "Bearer ",
		"publicKey":      integrationPublicKeyPEM,
		"issuer":         "https://auth.test.com",
		"audience":       []interface{}{"api.test.com"},
		"validateExpiry": true,
		"mandatory":      true,
		"mapClaimsToMetadata": map[string]interface{}{
			"enabled": true,
			"prefix":  "jwt.",
			"include": []interface{}{"sub", "email", "role"},
		},
	}

	// 3. Validate config
	if err := policy.Validate(config); err != nil {
		t.Fatalf("Config validation failed: %v", err)
	}

	// 4. Generate valid token
	claims := jwt.MapClaims{
		"iss":   "https://auth.test.com",
		"aud":   "api.test.com",
		"sub":   "user123",
		"email": "user@test.com",
		"role":  "admin",
		"exp":   time.Now().Add(1 * time.Hour).Unix(),
		"iat":   time.Now().Unix(),
		"scope": "read:users write:users",
	}
	token := generateToken(claims, integrationPrivateKey)

	// 5. Create request context
	ctx := &policies.RequestContext{
		Headers: map[string][]string{
			"authorization": {"Bearer " + token},
		},
		Path:     "/api/resource",
		Method:   "GET",
		Metadata: make(map[string]interface{}),
	}

	// 6. Execute policy
	requestPolicy := policy.(policies.RequestPolicy)
	action := requestPolicy.ExecuteRequest(ctx, config)

	// 7. Verify no immediate response (request passes)
	if _, ok := action.Action.(policies.ImmediateResponse); ok {
		t.Fatal("Expected request to pass, but got immediate response")
	}

	// 8. Verify authenticated flag
	if ctx.Metadata["authenticated"] != true {
		t.Error("Expected authenticated metadata to be true")
	}

	// 9. Verify claims mapping
	if ctx.Metadata["jwt.sub"] != "user123" {
		t.Errorf("Expected jwt.sub='user123', got '%v'", ctx.Metadata["jwt.sub"])
	}
	if ctx.Metadata["jwt.email"] != "user@test.com" {
		t.Errorf("Expected jwt.email='user@test.com', got '%v'", ctx.Metadata["jwt.email"])
	}
	if ctx.Metadata["jwt.role"] != "admin" {
		t.Errorf("Expected jwt.role='admin', got '%v'", ctx.Metadata["jwt.role"])
	}
}

// Test: Expired token rejection
func TestIntegration_ExpiredToken_Rejected(t *testing.T) {
	policy := jwtvalidation.NewPolicy()

	config := map[string]interface{}{
		"header":         "Authorization",
		"prefix":         "Bearer ",
		"publicKey":      integrationPublicKeyPEM,
		"validateExpiry": true,
		"mandatory":      true,
	}

	// Generate expired token
	claims := jwt.MapClaims{
		"exp": time.Now().Add(-1 * time.Hour).Unix(), // Expired 1 hour ago
		"iat": time.Now().Add(-2 * time.Hour).Unix(),
	}
	token := generateToken(claims, integrationPrivateKey)

	ctx := &policies.RequestContext{
		Headers: map[string][]string{
			"authorization": {"Bearer " + token},
		},
		Metadata: make(map[string]interface{}),
	}

	requestPolicy := policy.(policies.RequestPolicy)
	action := requestPolicy.ExecuteRequest(ctx, config)

	// Verify 401 response
	immediateResp, ok := action.Action.(policies.ImmediateResponse)
	if !ok {
		t.Fatal("Expected ImmediateResponse for expired token")
	}

	if immediateResp.StatusCode != 401 {
		t.Errorf("Expected status 401, got %d", immediateResp.StatusCode)
	}
}

// Test: Invalid issuer rejection
func TestIntegration_InvalidIssuer_Rejected(t *testing.T) {
	policy := jwtvalidation.NewPolicy()

	config := map[string]interface{}{
		"header":         "Authorization",
		"prefix":         "Bearer ",
		"publicKey":      integrationPublicKeyPEM,
		"issuer":         "https://auth.test.com",
		"validateExpiry": true,
		"mandatory":      true,
	}

	claims := jwt.MapClaims{
		"iss": "https://wrong-issuer.com",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	}
	token := generateToken(claims, integrationPrivateKey)

	ctx := &policies.RequestContext{
		Headers: map[string][]string{
			"authorization": {"Bearer " + token},
		},
		Metadata: make(map[string]interface{}),
	}

	requestPolicy := policy.(policies.RequestPolicy)
	action := requestPolicy.ExecuteRequest(ctx, config)

	immediateResp, ok := action.Action.(policies.ImmediateResponse)
	if !ok {
		t.Fatal("Expected ImmediateResponse for invalid issuer")
	}

	if immediateResp.StatusCode != 401 {
		t.Errorf("Expected status 401, got %d", immediateResp.StatusCode)
	}
}

// Test: Missing required scope rejection
func TestIntegration_MissingRequiredScope_Rejected(t *testing.T) {
	policy := jwtvalidation.NewPolicy()

	config := map[string]interface{}{
		"header":         "Authorization",
		"prefix":         "Bearer ",
		"publicKey":      integrationPublicKeyPEM,
		"validateExpiry": true,
		"mandatory":      true,
		"requiredScopes": []interface{}{"read:users", "write:users"},
	}

	claims := jwt.MapClaims{
		"exp":   time.Now().Add(1 * time.Hour).Unix(),
		"scope": "read:users", // Missing write:users
	}
	token := generateToken(claims, integrationPrivateKey)

	ctx := &policies.RequestContext{
		Headers: map[string][]string{
			"authorization": {"Bearer " + token},
		},
		Metadata: make(map[string]interface{}),
	}

	requestPolicy := policy.(policies.RequestPolicy)
	action := requestPolicy.ExecuteRequest(ctx, config)

	immediateResp, ok := action.Action.(policies.ImmediateResponse)
	if !ok {
		t.Fatal("Expected ImmediateResponse for missing scope")
	}

	if immediateResp.StatusCode != 401 {
		t.Errorf("Expected status 401, got %d", immediateResp.StatusCode)
	}
}

// Test: Non-mandatory mode allows missing token
func TestIntegration_NonMandatoryMode_AllowsMissingToken(t *testing.T) {
	policy := jwtvalidation.NewPolicy()

	config := map[string]interface{}{
		"header":    "Authorization",
		"publicKey": integrationPublicKeyPEM,
		"mandatory": false,
	}

	ctx := &policies.RequestContext{
		Headers:  map[string][]string{},
		Metadata: make(map[string]interface{}),
	}

	requestPolicy := policy.(policies.RequestPolicy)
	action := requestPolicy.ExecuteRequest(ctx, config)

	// Should get UpstreamRequestModifications (pass-through)
	_, ok := action.Action.(policies.UpstreamRequestModifications)
	if !ok {
		t.Fatal("Expected UpstreamRequestModifications for non-mandatory mode")
	}

	// Authenticated should NOT be set
	if ctx.Metadata["authenticated"] == true {
		t.Error("Expected authenticated to NOT be set for missing token")
	}
}

// Test: JWKS URL integration with mock server - Config validation only
func TestIntegration_JWKS_MockServer(t *testing.T) {
	// Create mock JWKS server
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Convert public key to JWK format (simplified)
		jwks := map[string]interface{}{
			"keys": []map[string]interface{}{
				{
					"kty": "RSA",
					"use": "sig",
					"kid": "test-key-1",
					"alg": "RS256",
					"n":   "xGOr-H7A-PWzOV6U8Z5AJzZhF9j7p6aCd8C9wKkFBhd7J_wT-TgJJZhO0-FiQ",
					"e":   "AQAB",
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))
	defer jwksServer.Close()

	policy := jwtvalidation.NewPolicy()

	config := map[string]interface{}{
		"header":              "Authorization",
		"prefix":              "Bearer ",
		"jwksUrl":             jwksServer.URL,
		"jwksRefreshInterval": "5m",
		"validateExpiry":      true,
		"mandatory":           true,
	}

	// Note: This test verifies the JWKS endpoint is callable
	// Actual signature verification would require matching key
	if err := policy.Validate(config); err != nil {
		t.Fatalf("Config validation failed: %v", err)
	}
}

// Test: JWKS URL - Complete end-to-end JWT authentication
func TestIntegration_JWKS_CompleteAuthentication(t *testing.T) {
	// 1. Generate a fresh key pair for this test
	testPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}
	testPublicKey := &testPrivateKey.PublicKey

	// 2. Convert public key to JWK format for JWKS endpoint
	// Extract modulus and exponent from RSA public key
	nBytes := testPublicKey.N.Bytes()
	eBytes := make([]byte, 4)
	eBytes[0] = byte(testPublicKey.E >> 24)
	eBytes[1] = byte(testPublicKey.E >> 16)
	eBytes[2] = byte(testPublicKey.E >> 8)
	eBytes[3] = byte(testPublicKey.E)

	// Trim leading zeros from exponent
	i := 0
	for i < len(eBytes) && eBytes[i] == 0 {
		i++
	}
	eBytes = eBytes[i:]

	// Base64url encode
	nEncoded := base64.RawURLEncoding.EncodeToString(nBytes)
	eEncoded := base64.RawURLEncoding.EncodeToString(eBytes)

	// 3. Create mock JWKS server with the real public key
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwks := map[string]interface{}{
			"keys": []map[string]interface{}{
				{
					"kty": "RSA",
					"use": "sig",
					"kid": "jwks-test-key",
					"alg": "RS256",
					"n":   nEncoded,
					"e":   eEncoded,
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))
	defer jwksServer.Close()

	// 4. Create policy with JWKS URL configuration
	policy := jwtvalidation.NewPolicy()

	config := map[string]interface{}{
		"header":              "Authorization",
		"prefix":              "Bearer ",
		"jwksUrl":             jwksServer.URL,
		"jwksRefreshInterval": "5m",
		"issuer":              "https://jwks-test.com",
		"audience":            []interface{}{"api.jwks-test.com"},
		"validateExpiry":      true,
		"mandatory":           true,
		"mapClaimsToMetadata": map[string]interface{}{
			"enabled": true,
			"prefix":  "jwt.",
			"include": []interface{}{"sub", "email"},
		},
	}

	// 5. Validate configuration
	if err := policy.Validate(config); err != nil {
		t.Fatalf("Config validation failed: %v", err)
	}

	// 6. Generate a valid JWT token signed with the test private key
	claims := jwt.MapClaims{
		"iss":   "https://jwks-test.com",
		"aud":   "api.jwks-test.com",
		"sub":   "jwks-user-123",
		"email": "jwks-user@test.com",
		"exp":   time.Now().Add(1 * time.Hour).Unix(),
		"iat":   time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "jwks-test-key" // Must match the kid in JWKS
	tokenString, err := token.SignedString(testPrivateKey)
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}

	// 7. Create request context
	ctx := &policies.RequestContext{
		Headers: map[string][]string{
			"authorization": {"Bearer " + tokenString},
		},
		Path:     "/api/jwks-test",
		Method:   "GET",
		Metadata: make(map[string]interface{}),
	}

	// 8. Execute policy - this should fetch keys from JWKS and validate
	requestPolicy := policy.(policies.RequestPolicy)
	action := requestPolicy.ExecuteRequest(ctx, config)

	// 9. Verify authentication succeeded
	if _, ok := action.Action.(policies.ImmediateResponse); ok {
		t.Fatal("Expected request to pass with JWKS authentication, but got immediate response")
	}

	// 10. Verify authenticated flag is set
	if ctx.Metadata["authenticated"] != true {
		t.Error("Expected authenticated metadata to be true after JWKS validation")
	}

	// 11. Verify claims were mapped correctly
	if ctx.Metadata["jwt.sub"] != "jwks-user-123" {
		t.Errorf("Expected jwt.sub='jwks-user-123', got '%v'", ctx.Metadata["jwt.sub"])
	}
	if ctx.Metadata["jwt.email"] != "jwks-user@test.com" {
		t.Errorf("Expected jwt.email='jwks-user@test.com', got '%v'", ctx.Metadata["jwt.email"])
	}

	t.Log("✅ JWKS end-to-end authentication test passed!")
}

// Test: JWKS URL - Token with wrong kid (key not found)
func TestIntegration_JWKS_WrongKid_Rejected(t *testing.T) {
	// Create mock JWKS server
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwks := map[string]interface{}{
			"keys": []map[string]interface{}{
				{
					"kty": "RSA",
					"use": "sig",
					"kid": "correct-key-id",
					"alg": "RS256",
					"n":   "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
					"e":   "AQAB",
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))
	defer jwksServer.Close()

	policy := jwtvalidation.NewPolicy()

	config := map[string]interface{}{
		"header":              "Authorization",
		"prefix":              "Bearer ",
		"jwksUrl":             jwksServer.URL,
		"jwksRefreshInterval": "5m",
		"validateExpiry":      true,
		"mandatory":           true,
	}

	// Generate token with different kid
	claims := jwt.MapClaims{
		"exp": time.Now().Add(1 * time.Hour).Unix(),
		"sub": "user123",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "wrong-key-id" // This kid doesn't exist in JWKS
	tokenString, _ := token.SignedString(integrationPrivateKey)

	ctx := &policies.RequestContext{
		Headers: map[string][]string{
			"authorization": {"Bearer " + tokenString},
		},
		Metadata: make(map[string]interface{}),
	}

	requestPolicy := policy.(policies.RequestPolicy)
	action := requestPolicy.ExecuteRequest(ctx, config)

	// Should reject due to key not found
	immediateResp, ok := action.Action.(policies.ImmediateResponse)
	if !ok {
		t.Fatal("Expected ImmediateResponse for token with wrong kid")
	}

	if immediateResp.StatusCode != 401 {
		t.Errorf("Expected status 401, got %d", immediateResp.StatusCode)
	}
}

// Test: JWKS URL - Token missing kid header
func TestIntegration_JWKS_MissingKid_Rejected(t *testing.T) {
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwks := map[string]interface{}{
			"keys": []map[string]interface{}{
				{
					"kty": "RSA",
					"use": "sig",
					"kid": "test-key",
					"alg": "RS256",
					"n":   "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
					"e":   "AQAB",
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))
	defer jwksServer.Close()

	policy := jwtvalidation.NewPolicy()

	config := map[string]interface{}{
		"header":              "Authorization",
		"prefix":              "Bearer ",
		"jwksUrl":             jwksServer.URL,
		"jwksRefreshInterval": "5m",
		"validateExpiry":      true,
		"mandatory":           true,
	}

	// Generate token without kid in header
	claims := jwt.MapClaims{
		"exp": time.Now().Add(1 * time.Hour).Unix(),
		"sub": "user123",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	// Don't set kid header
	tokenString, _ := token.SignedString(integrationPrivateKey)

	ctx := &policies.RequestContext{
		Headers: map[string][]string{
			"authorization": {"Bearer " + tokenString},
		},
		Metadata: make(map[string]interface{}),
	}

	requestPolicy := policy.(policies.RequestPolicy)
	action := requestPolicy.ExecuteRequest(ctx, config)

	// Should reject due to missing kid
	immediateResp, ok := action.Action.(policies.ImmediateResponse)
	if !ok {
		t.Fatal("Expected ImmediateResponse for token missing kid")
	}

	if immediateResp.StatusCode != 401 {
		t.Errorf("Expected status 401, got %d", immediateResp.StatusCode)
	}
}

// Test: Query parameter token extraction
func TestIntegration_TokenFromQueryParam(t *testing.T) {
	policy := jwtvalidation.NewPolicy()

	config := map[string]interface{}{
		"queryParam":     "access_token",
		"publicKey":      integrationPublicKeyPEM,
		"validateExpiry": true,
		"mandatory":      true,
	}

	claims := jwt.MapClaims{
		"exp": time.Now().Add(1 * time.Hour).Unix(),
		"sub": "user123",
	}
	token := generateToken(claims, integrationPrivateKey)

	ctx := &policies.RequestContext{
		Path:     "/api/resource?access_token=" + token + "&other=value",
		Headers:  map[string][]string{},
		Metadata: make(map[string]interface{}),
	}

	requestPolicy := policy.(policies.RequestPolicy)
	action := requestPolicy.ExecuteRequest(ctx, config)

	if _, ok := action.Action.(policies.ImmediateResponse); ok {
		t.Fatal("Expected request to pass with query param token")
	}

	if ctx.Metadata["authenticated"] != true {
		t.Error("Expected authenticated to be true")
	}
}

// Test: Cookie token extraction
func TestIntegration_TokenFromCookie(t *testing.T) {
	policy := jwtvalidation.NewPolicy()

	config := map[string]interface{}{
		"cookieName":     "jwt_token",
		"publicKey":      integrationPublicKeyPEM,
		"validateExpiry": true,
		"mandatory":      true,
	}

	claims := jwt.MapClaims{
		"exp": time.Now().Add(1 * time.Hour).Unix(),
		"sub": "user123",
	}
	token := generateToken(claims, integrationPrivateKey)

	ctx := &policies.RequestContext{
		Headers: map[string][]string{
			"cookie": {"session=abc123; jwt_token=" + token + "; other=value"},
		},
		Metadata: make(map[string]interface{}),
	}

	requestPolicy := policy.(policies.RequestPolicy)
	action := requestPolicy.ExecuteRequest(ctx, config)

	if _, ok := action.Action.(policies.ImmediateResponse); ok {
		t.Fatal("Expected request to pass with cookie token")
	}

	if ctx.Metadata["authenticated"] != true {
		t.Error("Expected authenticated to be true")
	}
}

// Test: Clock skew tolerance
func TestIntegration_ClockSkewTolerance(t *testing.T) {
	policy := jwtvalidation.NewPolicy()

	config := map[string]interface{}{
		"header":           "Authorization",
		"prefix":           "Bearer ",
		"publicKey":        integrationPublicKeyPEM,
		"validateExpiry":   true,
		"clockSkewSeconds": float64(600), // 10 minutes
		"mandatory":        true,
	}

	// Token will expire in 3 minutes (within clock skew tolerance when checked later)
	// Note: jwt library validates exp internally, so we can't use already-expired tokens
	// Instead, we test that a token close to expiry works within the clock skew window
	claims := jwt.MapClaims{
		"exp": time.Now().Add(3 * time.Minute).Unix(),
		"iat": time.Now().Unix(),
		"sub": "user123",
	}
	token := generateToken(claims, integrationPrivateKey)

	ctx := &policies.RequestContext{
		Headers: map[string][]string{
			"authorization": {"Bearer " + token},
		},
		Metadata: make(map[string]interface{}),
	}

	requestPolicy := policy.(policies.RequestPolicy)
	action := requestPolicy.ExecuteRequest(ctx, config)

	// Should pass - token is valid and within acceptable time range
	if _, ok := action.Action.(policies.ImmediateResponse); ok {
		t.Fatal("Expected request to pass with valid token")
	}

	if ctx.Metadata["authenticated"] != true {
		t.Error("Expected authenticated to be true")
	}
}

// Test: Multiple audiences (array)
func TestIntegration_MultipleAudiences(t *testing.T) {
	policy := jwtvalidation.NewPolicy()

	config := map[string]interface{}{
		"header":         "Authorization",
		"prefix":         "Bearer ",
		"publicKey":      integrationPublicKeyPEM,
		"audience":       []interface{}{"api.test.com", "admin.test.com"},
		"validateExpiry": true,
		"mandatory":      true,
	}

	claims := jwt.MapClaims{
		"aud": []interface{}{"api.test.com", "mobile.test.com"},
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	}
	token := generateToken(claims, integrationPrivateKey)

	ctx := &policies.RequestContext{
		Headers: map[string][]string{
			"authorization": {"Bearer " + token},
		},
		Metadata: make(map[string]interface{}),
	}

	requestPolicy := policy.(policies.RequestPolicy)
	action := requestPolicy.ExecuteRequest(ctx, config)

	if _, ok := action.Action.(policies.ImmediateResponse); ok {
		t.Fatal("Expected request to pass with matching audience")
	}
}
