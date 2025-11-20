package jwtvalidation

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/envoy-policy-engine/sdk/policies"
	"github.com/golang-jwt/jwt/v5"
)

// Test fixtures
var (
	testPrivateKey *rsa.PrivateKey
	testPublicKey  *rsa.PublicKey
)

func init() {
	// Generate RSA key pair for testing
	var err error
	testPrivateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	testPublicKey = &testPrivateKey.PublicKey
}

// Helper function to generate test JWT tokens
func generateTestToken(claims jwt.MapClaims, key *rsa.PrivateKey) string {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "test-key-1"

	tokenString, err := token.SignedString(key)
	if err != nil {
		panic(err)
	}
	return tokenString
}

// Helper to convert RSA public key to PEM
func publicKeyToPEM(key *rsa.PublicKey) string {
	// This is a simplified version - in real tests you'd use proper PEM encoding
	return "-----BEGIN PUBLIC KEY-----\ntest-key-data\n-----END PUBLIC KEY-----"
}

// Test 1: Policy Name
func TestJWTValidationPolicy_Name(t *testing.T) {
	policy := NewPolicy()

	if policy.Name() != "jwtValidation" {
		t.Errorf("Expected policy name 'jwtValidation', got '%s'", policy.Name())
	}
}

// Test 3: Configuration Validation - Valid Config
func TestJWTValidationPolicy_Validate_ValidConfig(t *testing.T) {
	policy := &JWTValidationPolicy{}

	// Use a real public key PEM or skip PEM validation in this test
	config := map[string]interface{}{
		"header":   "Authorization",
		"jwksUrl":  "https://auth.example.com/.well-known/jwks.json",
		"issuer":   "https://auth.example.com",
		"audience": []interface{}{"api.example.com"},
	}

	err := policy.Validate(config)
	if err != nil {
		t.Errorf("Expected valid config to pass validation, got error: %v", err)
	}
}

// Test 3: Configuration Validation - Missing Token Extraction Method
func TestJWTValidationPolicy_Validate_MissingTokenExtraction(t *testing.T) {
	policy := &JWTValidationPolicy{}

	config := map[string]interface{}{
		"publicKey": "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----",
	}

	err := policy.Validate(config)
	if err == nil {
		t.Error("Expected error for missing token extraction method, got nil")
	}
}

// Test 4: Configuration Validation - Missing Verification Method
func TestJWTValidationPolicy_Validate_MissingVerification(t *testing.T) {
	policy := &JWTValidationPolicy{}

	config := map[string]interface{}{
		"header": "Authorization",
	}

	err := policy.Validate(config)
	if err == nil {
		t.Error("Expected error for missing verification method, got nil")
	}
}

// Test 5: Token Extraction - From Header with Bearer Prefix
func TestJWTValidationPolicy_ExtractToken_FromHeader(t *testing.T) {
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

	token, err := policy.extractToken(ctx, config)
	if err != nil {
		t.Errorf("Expected successful token extraction, got error: %v", err)
	}

	if token != "test-token-123" {
		t.Errorf("Expected token 'test-token-123', got '%s'", token)
	}
}

// Test 6: Token Extraction - From Query Parameter
func TestJWTValidationPolicy_ExtractToken_FromQuery(t *testing.T) {
	policy := &JWTValidationPolicy{}

	ctx := &policies.RequestContext{
		Path:    "/api/resource?token=query-token-456&other=value",
		Headers: map[string][]string{},
	}

	config := map[string]interface{}{
		"queryParam": "token",
	}

	token, err := policy.extractToken(ctx, config)
	if err != nil {
		t.Errorf("Expected successful token extraction, got error: %v", err)
	}

	if token != "query-token-456" {
		t.Errorf("Expected token 'query-token-456', got '%s'", token)
	}
}

// Test 7: Token Extraction - From Cookie
func TestJWTValidationPolicy_ExtractToken_FromCookie(t *testing.T) {
	policy := &JWTValidationPolicy{}

	ctx := &policies.RequestContext{
		Headers: map[string][]string{
			"cookie": {"session=abc123; jwt_token=cookie-token-789; other=value"},
		},
	}

	config := map[string]interface{}{
		"cookieName": "jwt_token",
	}

	token, err := policy.extractToken(ctx, config)
	if err != nil {
		t.Errorf("Expected successful token extraction, got error: %v", err)
	}

	if token != "cookie-token-789" {
		t.Errorf("Expected token 'cookie-token-789', got '%s'", token)
	}
}

// Test 8: Token Extraction - Not Found
func TestJWTValidationPolicy_ExtractToken_NotFound(t *testing.T) {
	policy := &JWTValidationPolicy{}

	ctx := &policies.RequestContext{
		Headers: map[string][]string{},
	}

	config := map[string]interface{}{
		"header": "Authorization",
	}

	_, err := policy.extractToken(ctx, config)
	if err == nil {
		t.Error("Expected error when token not found, got nil")
	}
}

// Test 9: Claims Validation - Valid Issuer
func TestJWTValidationPolicy_ValidateClaims_ValidIssuer(t *testing.T) {
	policy := &JWTValidationPolicy{}

	claims := jwt.MapClaims{
		"iss": "https://auth.example.com",
		"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
	}

	config := map[string]interface{}{
		"issuer":         "https://auth.example.com",
		"validateExpiry": true,
	}

	err := policy.validateClaims(claims, config)
	if err != nil {
		t.Errorf("Expected valid claims to pass, got error: %v", err)
	}
}

// Test 10: Claims Validation - Invalid Issuer
func TestJWTValidationPolicy_ValidateClaims_InvalidIssuer(t *testing.T) {
	policy := &JWTValidationPolicy{}

	claims := jwt.MapClaims{
		"iss": "https://wrong-issuer.com",
		"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
	}

	config := map[string]interface{}{
		"issuer":         "https://auth.example.com",
		"validateExpiry": true,
	}

	err := policy.validateClaims(claims, config)
	if err == nil {
		t.Error("Expected error for invalid issuer, got nil")
	}
}

// Test 11: Claims Validation - Expired Token
func TestJWTValidationPolicy_ValidateClaims_ExpiredToken(t *testing.T) {
	policy := &JWTValidationPolicy{}

	claims := jwt.MapClaims{
		"exp": float64(time.Now().Add(-1 * time.Hour).Unix()), // Expired 1 hour ago
	}

	config := map[string]interface{}{
		"validateExpiry": true,
	}

	err := policy.validateClaims(claims, config)
	if err == nil {
		t.Error("Expected error for expired token, got nil")
	}
}

// Test 12: Claims Validation - Not Before (nbf)
func TestJWTValidationPolicy_ValidateClaims_NotYetValid(t *testing.T) {
	policy := &JWTValidationPolicy{}

	claims := jwt.MapClaims{
		"exp": float64(time.Now().Add(2 * time.Hour).Unix()),
		"nbf": float64(time.Now().Add(1 * time.Hour).Unix()), // Valid in 1 hour
	}

	config := map[string]interface{}{
		"validateExpiry":    true,
		"validateNotBefore": true,
	}

	err := policy.validateClaims(claims, config)
	if err == nil {
		t.Error("Expected error for not-yet-valid token, got nil")
	}
}

// Test 13: Claims Validation - Clock Skew
func TestJWTValidationPolicy_ValidateClaims_ClockSkew(t *testing.T) {
	policy := &JWTValidationPolicy{}

	// Token expired 2 minutes ago, but clock skew is 5 minutes
	claims := jwt.MapClaims{
		"exp": float64(time.Now().Add(-2 * time.Minute).Unix()),
	}

	config := map[string]interface{}{
		"validateExpiry":   true,
		"clockSkewSeconds": float64(300), // 5 minutes
	}

	err := policy.validateClaims(claims, config)
	if err != nil {
		t.Errorf("Expected token within clock skew to pass, got error: %v", err)
	}
}

// Test 14: Audience Validation - String Audience
func TestJWTValidationPolicy_ValidateAudience_String(t *testing.T) {
	policy := &JWTValidationPolicy{}

	claims := jwt.MapClaims{
		"aud": "api.example.com",
	}

	expectedAudiences := []interface{}{"api.example.com", "admin.example.com"}

	err := policy.validateAudience(claims, expectedAudiences)
	if err != nil {
		t.Errorf("Expected valid audience to pass, got error: %v", err)
	}
}

// Test 15: Audience Validation - Array Audience
func TestJWTValidationPolicy_ValidateAudience_Array(t *testing.T) {
	policy := &JWTValidationPolicy{}

	claims := jwt.MapClaims{
		"aud": []interface{}{"api.example.com", "mobile.example.com"},
	}

	expectedAudiences := []interface{}{"api.example.com"}

	err := policy.validateAudience(claims, expectedAudiences)
	if err != nil {
		t.Errorf("Expected valid audience to pass, got error: %v", err)
	}
}

// Test 16: Audience Validation - No Match
func TestJWTValidationPolicy_ValidateAudience_NoMatch(t *testing.T) {
	policy := &JWTValidationPolicy{}

	claims := jwt.MapClaims{
		"aud": "wrong.example.com",
	}

	expectedAudiences := []interface{}{"api.example.com"}

	err := policy.validateAudience(claims, expectedAudiences)
	if err == nil {
		t.Error("Expected error for mismatched audience, got nil")
	}
}

// Test 17: Scope Validation - Required Scopes (All Present)
func TestJWTValidationPolicy_ValidateScopes_RequiredPresent(t *testing.T) {
	policy := &JWTValidationPolicy{}

	claims := jwt.MapClaims{
		"scope": "read:users write:users delete:users",
	}

	config := map[string]interface{}{
		"scopeClaim":     "scope",
		"requiredScopes": []interface{}{"read:users", "write:users"},
	}

	err := policy.validateScopes(claims, config)
	if err != nil {
		t.Errorf("Expected all required scopes to pass, got error: %v", err)
	}
}

// Test 18: Scope Validation - Required Scopes (Missing)
func TestJWTValidationPolicy_ValidateScopes_RequiredMissing(t *testing.T) {
	policy := &JWTValidationPolicy{}

	claims := jwt.MapClaims{
		"scope": "read:users",
	}

	config := map[string]interface{}{
		"scopeClaim":     "scope",
		"requiredScopes": []interface{}{"read:users", "write:users"},
	}

	err := policy.validateScopes(claims, config)
	if err == nil {
		t.Error("Expected error for missing required scope, got nil")
	}
}

// Test 19: Scope Validation - Optional Scopes (At Least One)
func TestJWTValidationPolicy_ValidateScopes_OptionalPresent(t *testing.T) {
	policy := &JWTValidationPolicy{}

	claims := jwt.MapClaims{
		"scope": "read:users",
	}

	config := map[string]interface{}{
		"scopeClaim":     "scope",
		"optionalScopes": []interface{}{"read:users", "admin:all"},
	}

	err := policy.validateScopes(claims, config)
	if err != nil {
		t.Errorf("Expected at least one optional scope to pass, got error: %v", err)
	}
}

// Test 20: Scope Validation - Optional Scopes (None Present)
func TestJWTValidationPolicy_ValidateScopes_OptionalMissing(t *testing.T) {
	policy := &JWTValidationPolicy{}

	claims := jwt.MapClaims{
		"scope": "read:posts",
	}

	config := map[string]interface{}{
		"scopeClaim":     "scope",
		"optionalScopes": []interface{}{"read:users", "admin:all"},
	}

	err := policy.validateScopes(claims, config)
	if err == nil {
		t.Error("Expected error for no optional scopes present, got nil")
	}
}

// Test 21: Scope Validation - Array Format
func TestJWTValidationPolicy_ValidateScopes_ArrayFormat(t *testing.T) {
	policy := &JWTValidationPolicy{}

	claims := jwt.MapClaims{
		"scope": []interface{}{"read:users", "write:users"},
	}

	config := map[string]interface{}{
		"scopeClaim":     "scope",
		"requiredScopes": []interface{}{"read:users"},
	}

	err := policy.validateScopes(claims, config)
	if err != nil {
		t.Errorf("Expected array format scopes to pass, got error: %v", err)
	}
}

// Test 22: Claims to Metadata Mapping - Include List
func TestJWTValidationPolicy_MapClaimsToMetadata_Include(t *testing.T) {
	policy := &JWTValidationPolicy{}

	ctx := &policies.RequestContext{
		Metadata: make(map[string]interface{}),
	}

	claims := jwt.MapClaims{
		"sub":   "user123",
		"email": "user@example.com",
		"role":  "admin",
		"other": "should-not-be-included",
	}

	config := map[string]interface{}{
		"mapClaimsToMetadata": map[string]interface{}{
			"enabled": true,
			"prefix":  "jwt.",
			"include": []interface{}{"sub", "email", "role"},
		},
	}

	policy.mapClaimsToMetadata(ctx, claims, config)

	if ctx.Metadata["jwt.sub"] != "user123" {
		t.Error("Expected sub claim to be mapped")
	}
	if ctx.Metadata["jwt.email"] != "user@example.com" {
		t.Error("Expected email claim to be mapped")
	}
	if ctx.Metadata["jwt.role"] != "admin" {
		t.Error("Expected role claim to be mapped")
	}
	if _, exists := ctx.Metadata["jwt.other"]; exists {
		t.Error("Expected 'other' claim not to be mapped")
	}
}

// Test 23: Claims to Metadata Mapping - Exclude List
func TestJWTValidationPolicy_MapClaimsToMetadata_Exclude(t *testing.T) {
	policy := &JWTValidationPolicy{}

	ctx := &policies.RequestContext{
		Metadata: make(map[string]interface{}),
	}

	claims := jwt.MapClaims{
		"sub":   "user123",
		"email": "user@example.com",
		"exp":   float64(time.Now().Unix()),
	}

	config := map[string]interface{}{
		"mapClaimsToMetadata": map[string]interface{}{
			"enabled": true,
			"prefix":  "jwt.",
			"exclude": []interface{}{"exp"},
		},
	}

	policy.mapClaimsToMetadata(ctx, claims, config)

	if _, exists := ctx.Metadata["jwt.exp"]; exists {
		t.Error("Expected exp claim to be excluded")
	}
}

// Test 24: Claims to Metadata Mapping - Custom Prefix
func TestJWTValidationPolicy_MapClaimsToMetadata_CustomPrefix(t *testing.T) {
	policy := &JWTValidationPolicy{}

	ctx := &policies.RequestContext{
		Metadata: make(map[string]interface{}),
	}

	claims := jwt.MapClaims{
		"sub": "user123",
	}

	config := map[string]interface{}{
		"mapClaimsToMetadata": map[string]interface{}{
			"enabled": true,
			"prefix":  "auth.token.",
			"include": []interface{}{"sub"},
		},
	}

	policy.mapClaimsToMetadata(ctx, claims, config)

	if ctx.Metadata["auth.token.sub"] != "user123" {
		t.Error("Expected sub claim with custom prefix")
	}
}

// Test 25: Error Handling - Mandatory Mode (Returns 401)
func TestJWTValidationPolicy_HandleError_Mandatory(t *testing.T) {
	policy := &JWTValidationPolicy{}

	config := map[string]interface{}{
		"mandatory": true,
	}

	action := policy.handleError(config, "test error message")

	if action == nil {
		t.Fatal("Expected action to be returned")
	}

	immediateResp, ok := action.Action.(policies.ImmediateResponse)
	if !ok {
		t.Fatal("Expected ImmediateResponse action")
	}

	if immediateResp.StatusCode != 401 {
		t.Errorf("Expected status code 401, got %d", immediateResp.StatusCode)
	}

	if immediateResp.Headers["www-authenticate"] != "Bearer" {
		t.Error("Expected WWW-Authenticate header")
	}
}

// Test 26: Error Handling - Non-Mandatory Mode (Continues)
func TestJWTValidationPolicy_HandleError_NonMandatory(t *testing.T) {
	policy := &JWTValidationPolicy{}

	config := map[string]interface{}{
		"mandatory": false,
	}

	action := policy.handleError(config, "test error message")

	if action == nil {
		t.Fatal("Expected action to be returned")
	}

	_, ok := action.Action.(policies.UpstreamRequestModifications)
	if !ok {
		t.Fatal("Expected UpstreamRequestModifications action (pass-through)")
	}
}

// Test 27: JWKS - JWK to RSA Public Key Conversion
func TestJWKToRSAPublicKey(t *testing.T) {
	// Use a properly formatted base64url-encoded RSA modulus
	// This is a valid (but small for testing) RSA key component
	jwk := JWK{
		Kty: "RSA",
		// Valid base64url-encoded modulus (this is a real example from a small test key)
		N:   "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
		E:   "AQAB",
		Kid: "test-key",
	}

	key, err := jwkToRSAPublicKey(jwk)
	if err != nil {
		t.Errorf("Expected successful RSA key conversion, got error: %v", err)
	}

	if key == nil {
		t.Error("Expected non-nil RSA public key")
	}
}

// Test 28: JWKS - Mock Server Integration
func TestJWTValidationPolicy_JWKSIntegration(t *testing.T) {
	// Create mock JWKS server
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwks := JWKSet{
			Keys: []JWK{
				{
					Kty: "RSA",
					Use: "sig",
					Kid: "test-key-1",
					N:   "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
					E:   "AQAB",
					Alg: "RS256",
				},
			},
		}
		json.NewEncoder(w).Encode(jwks)
	}))
	defer jwksServer.Close()

	policy := NewPolicy().(*JWTValidationPolicy)

	err := policy.refreshJWKS(jwksServer.URL)
	if err != nil {
		t.Errorf("Expected successful JWKS refresh, got error: %v", err)
	}

	if len(policy.jwksCache.keys) == 0 {
		t.Error("Expected keys to be cached")
	}
}

// Test 29: Helper - Algorithm Allowed
func TestJWTValidationPolicy_IsAlgorithmAllowed(t *testing.T) {
	policy := &JWTValidationPolicy{}

	allowed := []string{"RS256", "ES256"}

	if !policy.isAlgorithmAllowed("RS256", allowed) {
		t.Error("Expected RS256 to be allowed")
	}

	if policy.isAlgorithmAllowed("HS256", allowed) {
		t.Error("Expected HS256 not to be allowed")
	}
}

// Test 30: Helper - Get Clock Skew
func TestJWTValidationPolicy_GetClockSkew(t *testing.T) {
	policy := &JWTValidationPolicy{}

	config := map[string]interface{}{
		"clockSkewSeconds": float64(600),
	}

	skew := policy.getClockSkew(config)
	if skew != 10*time.Minute {
		t.Errorf("Expected 10 minute clock skew, got %v", skew)
	}
}
