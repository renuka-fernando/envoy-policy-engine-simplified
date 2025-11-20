package jwtvalidation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/envoy-policy-engine/sdk/policies"
	"github.com/golang-jwt/jwt/v5"
)

// JWTValidationPolicy implements JWT authentication and validation
type JWTValidationPolicy struct {
	jwksCache *jwksCache
}

// jwksCache stores JWKS keys with refresh capability
type jwksCache struct {
	mu              sync.RWMutex
	keys            map[string]interface{} // kid -> public key
	lastRefresh     time.Time
	refreshURL      string
	refreshInterval time.Duration
}

// JWK represents a JSON Web Key
type JWK struct {
	Kty string `json:"kty"` // Key type (RSA, EC, etc.)
	Use string `json:"use"` // Key use (sig, enc)
	Kid string `json:"kid"` // Key ID
	Alg string `json:"alg"` // Algorithm
	N   string `json:"n"`   // RSA modulus
	E   string `json:"e"`   // RSA exponent
	X   string `json:"x"`   // EC x coordinate
	Y   string `json:"y"`   // EC y coordinate
	Crv string `json:"crv"` // EC curve
}

// JWKSet represents a set of JSON Web Keys
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

// NewPolicy creates a new JWTValidationPolicy instance
func NewPolicy() policies.Policy {
	return &JWTValidationPolicy{
		jwksCache: &jwksCache{
			keys: make(map[string]interface{}),
		},
	}
}

// Name returns the policy name
func (p *JWTValidationPolicy) Name() string {
	return "jwtValidation"
}

// Validate validates the policy configuration
func (p *JWTValidationPolicy) Validate(config map[string]interface{}) error {
	// Validate that at least one token extraction method is configured
	header, _ := config["header"].(string)
	queryParam, _ := config["queryParam"].(string)
	cookieName, _ := config["cookieName"].(string)

	if header == "" && queryParam == "" && cookieName == "" {
		return fmt.Errorf("at least one token extraction method must be configured (header, queryParam, or cookieName)")
	}

	// Validate that at least one verification method is configured
	jwksUrl, _ := config["jwksUrl"].(string)
	certificate, _ := config["certificate"].(string)
	publicKey, _ := config["publicKey"].(string)

	if jwksUrl == "" && certificate == "" && publicKey == "" {
		return fmt.Errorf("at least one signature verification method must be configured (jwksUrl, certificate, or publicKey)")
	}

	// Validate JWKS URL format if provided
	if jwksUrl != "" {
		if _, err := url.Parse(jwksUrl); err != nil {
			return fmt.Errorf("invalid jwksUrl: %w", err)
		}
	}

	// Validate public key format if provided
	if publicKey != "" {
		if err := validatePEMKey(publicKey); err != nil {
			return fmt.Errorf("invalid publicKey: %w", err)
		}
	}

	// Validate certificate format if provided
	if certificate != "" {
		if err := validatePEMCertificate(certificate); err != nil {
			return fmt.Errorf("invalid certificate: %w", err)
		}
	}

	// Validate allowed algorithms
	if algRaw, ok := config["allowedAlgorithms"]; ok {
		algs, ok := algRaw.([]interface{})
		if !ok {
			return fmt.Errorf("allowedAlgorithms must be an array")
		}
		if len(algs) == 0 {
			return fmt.Errorf("allowedAlgorithms cannot be empty")
		}
	}

	// Validate clock skew
	if skewRaw, ok := config["clockSkewSeconds"]; ok {
		skew, ok := skewRaw.(float64)
		if !ok {
			return fmt.Errorf("clockSkewSeconds must be a number")
		}
		if skew < 0 || skew > 3600 {
			return fmt.Errorf("clockSkewSeconds must be between 0 and 3600")
		}
	}

	return nil
}

// ExecuteRequest processes the JWT token during request phase
func (p *JWTValidationPolicy) ExecuteRequest(ctx *policies.RequestContext, config map[string]interface{}) *policies.RequestPolicyAction {
	// Extract token from request
	token, err := p.extractToken(ctx, config)
	if err != nil {
		return p.handleError(config, fmt.Sprintf("token extraction failed: %v", err))
	}

	if token == "" {
		return p.handleError(config, "no token found")
	}

	// Parse and validate JWT
	claims, err := p.validateToken(token, config)
	if err != nil {
		return p.handleError(config, fmt.Sprintf("token validation failed: %v", err))
	}

	// Validate claims
	if err := p.validateClaims(claims, config); err != nil {
		return p.handleError(config, fmt.Sprintf("claims validation failed: %v", err))
	}

	// Map claims to metadata
	p.mapClaimsToMetadata(ctx, claims, config)

	// Mark request as authenticated
	ctx.Metadata["authenticated"] = true

	// Continue with no modifications
	return &policies.RequestPolicyAction{
		Action: policies.UpstreamRequestModifications{},
	}
}

// extractToken extracts JWT token from header, query param, or cookie
func (p *JWTValidationPolicy) extractToken(ctx *policies.RequestContext, config map[string]interface{}) (string, error) {
	// Try header first
	if header, ok := config["header"].(string); ok && header != "" {
		if values, exists := ctx.Headers[strings.ToLower(header)]; exists && len(values) > 0 {
			token := values[0]

			// Remove prefix if configured
			if prefix, ok := config["prefix"].(string); ok && prefix != "" {
				token = strings.TrimPrefix(token, prefix)
			}

			return strings.TrimSpace(token), nil
		}
	}

	// Try query parameter
	if queryParam, ok := config["queryParam"].(string); ok && queryParam != "" {
		// Parse query string from path
		if idx := strings.Index(ctx.Path, "?"); idx != -1 {
			queryString := ctx.Path[idx+1:]
			values, err := url.ParseQuery(queryString)
			if err == nil {
				if token := values.Get(queryParam); token != "" {
					return token, nil
				}
			}
		}
	}

	// Try cookie
	if cookieName, ok := config["cookieName"].(string); ok && cookieName != "" {
		if cookieHeaders, exists := ctx.Headers["cookie"]; exists {
			for _, cookieHeader := range cookieHeaders {
				cookies := strings.Split(cookieHeader, ";")
				for _, cookie := range cookies {
					parts := strings.SplitN(strings.TrimSpace(cookie), "=", 2)
					if len(parts) == 2 && parts[0] == cookieName {
						return parts[1], nil
					}
				}
			}
		}
	}

	return "", fmt.Errorf("token not found in any configured source")
}

// validateToken parses and validates the JWT token
func (p *JWTValidationPolicy) validateToken(tokenString string, config map[string]interface{}) (jwt.MapClaims, error) {
	// Get allowed algorithms
	allowedAlgs := p.getAllowedAlgorithms(config)

	// Parse token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate algorithm
		alg := token.Method.Alg()
		if !p.isAlgorithmAllowed(alg, allowedAlgs) {
			return nil, fmt.Errorf("algorithm %s not allowed", alg)
		}

		// Get verification key
		return p.getVerificationKey(token, config)
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims format")
	}

	return claims, nil
}

// validateClaims validates JWT claims according to configuration
func (p *JWTValidationPolicy) validateClaims(claims jwt.MapClaims, config map[string]interface{}) error {
	now := time.Now()
	clockSkew := p.getClockSkew(config)

	// Validate expiry (exp)
	if p.getBoolConfig(config, "validateExpiry", true) {
		if exp, ok := claims["exp"].(float64); ok {
			expTime := time.Unix(int64(exp), 0)
			if now.After(expTime.Add(clockSkew)) {
				return fmt.Errorf("token expired")
			}
		} else {
			return fmt.Errorf("exp claim missing or invalid")
		}
	}

	// Validate not before (nbf)
	if p.getBoolConfig(config, "validateNotBefore", true) {
		if nbf, ok := claims["nbf"].(float64); ok {
			nbfTime := time.Unix(int64(nbf), 0)
			if now.Before(nbfTime.Add(-clockSkew)) {
				return fmt.Errorf("token not yet valid")
			}
		}
	}

	// Validate issuer (iss)
	if issuer, ok := config["issuer"].(string); ok && issuer != "" {
		claimIssuer, _ := claims["iss"].(string)
		if claimIssuer != issuer {
			return fmt.Errorf("invalid issuer: expected %s, got %s", issuer, claimIssuer)
		}
	}

	// Validate audience (aud)
	if audRaw, ok := config["audience"]; ok {
		if audList, ok := audRaw.([]interface{}); ok && len(audList) > 0 {
			if err := p.validateAudience(claims, audList); err != nil {
				return err
			}
		}
	}

	// Validate subject (sub)
	if subject, ok := config["subject"].(string); ok && subject != "" {
		claimSubject, _ := claims["sub"].(string)
		if claimSubject != subject {
			return fmt.Errorf("invalid subject: expected %s, got %s", subject, claimSubject)
		}
	}

	// Validate tenant
	if tenant, ok := config["tenant"].(string); ok && tenant != "" {
		claimTenant, _ := claims["tenant"].(string)
		if claimTenant != tenant {
			return fmt.Errorf("invalid tenant: expected %s, got %s", tenant, claimTenant)
		}
	}

	// Validate scopes
	if err := p.validateScopes(claims, config); err != nil {
		return err
	}

	return nil
}

// validateAudience validates the audience claim
func (p *JWTValidationPolicy) validateAudience(claims jwt.MapClaims, expectedAudiences []interface{}) error {
	audClaim, exists := claims["aud"]
	if !exists {
		return fmt.Errorf("aud claim missing")
	}

	// Handle both string and array audience claims
	var audiences []string
	switch aud := audClaim.(type) {
	case string:
		audiences = []string{aud}
	case []interface{}:
		for _, a := range aud {
			if audStr, ok := a.(string); ok {
				audiences = append(audiences, audStr)
			}
		}
	default:
		return fmt.Errorf("invalid aud claim format")
	}

	// Check if any token audience matches expected audiences
	for _, tokenAud := range audiences {
		for _, expectedAud := range expectedAudiences {
			if expectedAudStr, ok := expectedAud.(string); ok && tokenAud == expectedAudStr {
				return nil
			}
		}
	}

	return fmt.Errorf("no matching audience found")
}

// validateScopes validates required and optional scopes
func (p *JWTValidationPolicy) validateScopes(claims jwt.MapClaims, config map[string]interface{}) error {
	scopeClaim := "scope"
	if sc, ok := config["scopeClaim"].(string); ok && sc != "" {
		scopeClaim = sc
	}

	// Extract scopes from claims
	var tokenScopes []string
	if scopeRaw, exists := claims[scopeClaim]; exists {
		switch scopes := scopeRaw.(type) {
		case string:
			// Space-separated scopes (common format)
			tokenScopes = strings.Fields(scopes)
		case []interface{}:
			// Array of scopes
			for _, s := range scopes {
				if scopeStr, ok := s.(string); ok {
					tokenScopes = append(tokenScopes, scopeStr)
				}
			}
		}
	}

	// Validate required scopes (all must be present)
	if reqRaw, ok := config["requiredScopes"]; ok {
		if reqScopes, ok := reqRaw.([]interface{}); ok && len(reqScopes) > 0 {
			for _, reqScope := range reqScopes {
				if reqScopeStr, ok := reqScope.(string); ok {
					if !p.containsScope(tokenScopes, reqScopeStr) {
						return fmt.Errorf("missing required scope: %s", reqScopeStr)
					}
				}
			}
		}
	}

	// Validate optional scopes (at least one must be present)
	if optRaw, ok := config["optionalScopes"]; ok {
		if optScopes, ok := optRaw.([]interface{}); ok && len(optScopes) > 0 {
			hasOptional := false
			for _, optScope := range optScopes {
				if optScopeStr, ok := optScope.(string); ok {
					if p.containsScope(tokenScopes, optScopeStr) {
						hasOptional = true
						break
					}
				}
			}
			if !hasOptional {
				return fmt.Errorf("missing at least one optional scope")
			}
		}
	}

	return nil
}

// mapClaimsToMetadata maps JWT claims to request metadata
func (p *JWTValidationPolicy) mapClaimsToMetadata(ctx *policies.RequestContext, claims jwt.MapClaims, config map[string]interface{}) {
	mapConfigRaw, ok := config["mapClaimsToMetadata"]
	if !ok {
		return
	}

	mapConfig, ok := mapConfigRaw.(map[string]interface{})
	if !ok {
		return
	}

	// Check if mapping is enabled
	if enabled, ok := mapConfig["enabled"].(bool); !ok || !enabled {
		return
	}

	// Get prefix
	prefix := "jwt."
	if p, ok := mapConfig["prefix"].(string); ok {
		prefix = p
	}

	// Determine which claims to include
	var claimsToMap []string
	if includeRaw, ok := mapConfig["include"]; ok {
		if includeList, ok := includeRaw.([]interface{}); ok {
			for _, claim := range includeList {
				if claimStr, ok := claim.(string); ok {
					claimsToMap = append(claimsToMap, claimStr)
				}
			}
		}
	} else {
		// If no include list, map all claims
		for claim := range claims {
			claimsToMap = append(claimsToMap, claim)
		}
	}

	// Apply exclude filter
	excludeMap := make(map[string]bool)
	if excludeRaw, ok := mapConfig["exclude"]; ok {
		if excludeList, ok := excludeRaw.([]interface{}); ok {
			for _, claim := range excludeList {
				if claimStr, ok := claim.(string); ok {
					excludeMap[claimStr] = true
				}
			}
		}
	}

	// Map claims to metadata
	for _, claim := range claimsToMap {
		if excludeMap[claim] {
			continue
		}
		if value, exists := claims[claim]; exists {
			ctx.Metadata[prefix+claim] = value
		}
	}
}

// getVerificationKey retrieves the key for JWT signature verification
func (p *JWTValidationPolicy) getVerificationKey(token *jwt.Token, config map[string]interface{}) (interface{}, error) {
	// Try public key first
	if publicKeyPEM, ok := config["publicKey"].(string); ok && publicKeyPEM != "" {
		return parsePublicKey(publicKeyPEM)
	}

	// Try certificate
	if certPEM, ok := config["certificate"].(string); ok && certPEM != "" {
		return parseCertificate(certPEM)
	}

	// Try JWKS URL
	if jwksUrl, ok := config["jwksUrl"].(string); ok && jwksUrl != "" {
		// Get refresh interval
		refreshInterval := 5 * time.Minute // default
		if intervalStr, ok := config["jwksRefreshInterval"].(string); ok && intervalStr != "" {
			if d, err := time.ParseDuration(intervalStr); err == nil {
				refreshInterval = d
			}
		}

		// Initialize or refresh cache if needed
		if err := p.ensureJWKSCache(jwksUrl, refreshInterval); err != nil {
			return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
		}

		// Get key ID from token header
		kid, ok := token.Header["kid"].(string)
		if !ok || kid == "" {
			return nil, fmt.Errorf("token missing kid (key ID) header")
		}

		// Look up key by kid
		p.jwksCache.mu.RLock()
		key, exists := p.jwksCache.keys[kid]
		p.jwksCache.mu.RUnlock()

		if !exists {
			// Try refreshing cache and look again
			if err := p.refreshJWKS(jwksUrl); err == nil {
				p.jwksCache.mu.RLock()
				key, exists = p.jwksCache.keys[kid]
				p.jwksCache.mu.RUnlock()
			}

			if !exists {
				return nil, fmt.Errorf("key with kid %s not found in JWKS", kid)
			}
		}

		return key, nil
	}

	return nil, fmt.Errorf("no verification key available")
}

// handleError handles authentication failure based on mandatory flag
func (p *JWTValidationPolicy) handleError(config map[string]interface{}, message string) *policies.RequestPolicyAction {
	mandatory := p.getBoolConfig(config, "mandatory", true)

	if mandatory {
		// Return 401 Unauthorized
		return &policies.RequestPolicyAction{
			Action: policies.ImmediateResponse{
				StatusCode: 401,
				Headers: map[string]string{
					"content-type":     "application/json",
					"www-authenticate": "Bearer",
				},
				Body: []byte(fmt.Sprintf(`{"error":"unauthorized","message":"%s"}`, message)),
			},
		}
	}

	// Non-mandatory: continue without authentication
	return &policies.RequestPolicyAction{
		Action: policies.UpstreamRequestModifications{},
	}
}

// Helper functions

func (p *JWTValidationPolicy) getAllowedAlgorithms(config map[string]interface{}) []string {
	defaultAlgs := []string{"RS256", "ES256"}

	if algRaw, ok := config["allowedAlgorithms"]; ok {
		if algs, ok := algRaw.([]interface{}); ok {
			result := make([]string, 0, len(algs))
			for _, alg := range algs {
				if algStr, ok := alg.(string); ok {
					result = append(result, algStr)
				}
			}
			if len(result) > 0 {
				return result
			}
		}
	}

	return defaultAlgs
}

func (p *JWTValidationPolicy) isAlgorithmAllowed(alg string, allowed []string) bool {
	for _, a := range allowed {
		if a == alg {
			return true
		}
	}
	return false
}

func (p *JWTValidationPolicy) getClockSkew(config map[string]interface{}) time.Duration {
	skew := 300.0 // default 5 minutes
	if skewRaw, ok := config["clockSkewSeconds"]; ok {
		if s, ok := skewRaw.(float64); ok {
			skew = s
		}
	}
	return time.Duration(skew) * time.Second
}

func (p *JWTValidationPolicy) getBoolConfig(config map[string]interface{}, key string, defaultValue bool) bool {
	if value, ok := config[key].(bool); ok {
		return value
	}
	return defaultValue
}

func (p *JWTValidationPolicy) containsScope(scopes []string, target string) bool {
	for _, scope := range scopes {
		if scope == target {
			return true
		}
	}
	return false
}

// validatePEMKey validates PEM-encoded public key format
func validatePEMKey(pemKey string) error {
	block, _ := pem.Decode([]byte(pemKey))
	if block == nil {
		return fmt.Errorf("failed to decode PEM block")
	}

	if block.Type != "PUBLIC KEY" && block.Type != "RSA PUBLIC KEY" && block.Type != "EC PUBLIC KEY" {
		return fmt.Errorf("invalid PEM type: %s", block.Type)
	}

	return nil
}

// validatePEMCertificate validates PEM-encoded certificate format
func validatePEMCertificate(pemCert string) error {
	block, _ := pem.Decode([]byte(pemCert))
	if block == nil {
		return fmt.Errorf("failed to decode PEM block")
	}

	if block.Type != "CERTIFICATE" {
		return fmt.Errorf("invalid PEM type: %s", block.Type)
	}

	_, err := x509.ParseCertificate(block.Bytes)
	return err
}

// parsePublicKey parses a PEM-encoded public key
func parsePublicKey(pemKey string) (interface{}, error) {
	block, _ := pem.Decode([]byte(pemKey))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// Try parsing as PKIX public key first
	if key, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		return key, nil
	}

	// Try parsing as PKCS1 RSA public key
	if key, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return key, nil
	}

	return nil, fmt.Errorf("failed to parse public key")
}

// parseCertificate parses a PEM-encoded certificate and extracts public key
func parseCertificate(pemCert string) (interface{}, error) {
	block, _ := pem.Decode([]byte(pemCert))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert.PublicKey, nil
}

// parseJWT manually parses JWT without validation (for inspection)
func parseJWT(tokenString string) (map[string]interface{}, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}

	// Decode payload
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal claims: %w", err)
	}

	return claims, nil
}

// ensureJWKSCache ensures the JWKS cache is initialized and up-to-date
func (p *JWTValidationPolicy) ensureJWKSCache(jwksUrl string, refreshInterval time.Duration) error {
	p.jwksCache.mu.RLock()
	needsRefresh := p.jwksCache.refreshURL != jwksUrl ||
		time.Since(p.jwksCache.lastRefresh) > refreshInterval ||
		len(p.jwksCache.keys) == 0
	p.jwksCache.mu.RUnlock()

	if needsRefresh {
		return p.refreshJWKS(jwksUrl)
	}

	return nil
}

// refreshJWKS fetches and updates the JWKS cache from the URL
func (p *JWTValidationPolicy) refreshJWKS(jwksUrl string) error {
	// Fetch JWKS from URL
	resp, err := http.Get(jwksUrl)
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read JWKS response: %w", err)
	}

	// Parse JWKS
	var jwks JWKSet
	if err := json.Unmarshal(body, &jwks); err != nil {
		return fmt.Errorf("failed to parse JWKS: %w", err)
	}

	// Convert JWKs to public keys
	keys := make(map[string]interface{})
	for _, jwk := range jwks.Keys {
		key, err := jwkToPublicKey(jwk)
		if err != nil {
			// Skip invalid keys but don't fail the entire refresh
			continue
		}
		if jwk.Kid != "" {
			keys[jwk.Kid] = key
		}
	}

	if len(keys) == 0 {
		return fmt.Errorf("no valid keys found in JWKS")
	}

	// Update cache
	p.jwksCache.mu.Lock()
	p.jwksCache.keys = keys
	p.jwksCache.refreshURL = jwksUrl
	p.jwksCache.lastRefresh = time.Now()
	p.jwksCache.mu.Unlock()

	return nil
}

// jwkToPublicKey converts a JWK to a public key interface
func jwkToPublicKey(jwk JWK) (interface{}, error) {
	switch jwk.Kty {
	case "RSA":
		return jwkToRSAPublicKey(jwk)
	case "EC":
		return jwkToECPublicKey(jwk)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", jwk.Kty)
	}
}

// jwkToRSAPublicKey converts a JWK to an RSA public key
func jwkToRSAPublicKey(jwk JWK) (interface{}, error) {
	if jwk.N == "" || jwk.E == "" {
		return nil, fmt.Errorf("RSA JWK missing n or e parameter")
	}

	// Decode modulus (n)
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode RSA modulus: %w", err)
	}

	// Decode exponent (e)
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode RSA exponent: %w", err)
	}

	// Convert exponent bytes to int
	var e int
	for _, b := range eBytes {
		e = e<<8 | int(b)
	}

	// Create RSA public key
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: e,
	}, nil
}

// jwkToECPublicKey converts a JWK to an EC public key
func jwkToECPublicKey(jwk JWK) (interface{}, error) {
	if jwk.X == "" || jwk.Y == "" || jwk.Crv == "" {
		return nil, fmt.Errorf("EC JWK missing x, y, or crv parameter")
	}

	// Decode x coordinate
	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("failed to decode EC x coordinate: %w", err)
	}

	// Decode y coordinate
	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, fmt.Errorf("failed to decode EC y coordinate: %w", err)
	}

	// Get curve
	var curve elliptic.Curve
	switch jwk.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported EC curve: %s", jwk.Crv)
	}

	// Create EC public key
	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}
