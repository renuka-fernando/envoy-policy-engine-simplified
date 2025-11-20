package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	privateKeyFile = flag.String("key", "test-private.pem", "Path to private key file")
	issuer         = flag.String("iss", "https://auth.test.com", "Issuer (iss) claim")
	audience       = flag.String("aud", "api.test.com", "Audience (aud) claim")
	subject        = flag.String("sub", "user123", "Subject (sub) claim")
	email          = flag.String("email", "user@test.com", "Email claim")
	role           = flag.String("role", "admin", "Role claim")
	scopes         = flag.String("scopes", "read:users write:users", "Space-separated scopes")
	expiry         = flag.Duration("exp", 1*time.Hour, "Token expiry duration")
	expired        = flag.Bool("expired", false, "Generate expired token")
	generateKeys   = flag.Bool("generate-keys", false, "Generate new RSA key pair")
	kid            = flag.String("kid", "test-key-1", "Key ID (kid) header")
)

func main() {
	flag.Parse()

	if *generateKeys {
		if err := generateKeyPair(); err != nil {
			fmt.Fprintf(os.Stderr, "Error generating keys: %v\n", err)
			os.Exit(1)
		}
		return
	}

	token, err := generateToken()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating token: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("=== JWT Token ===")
	fmt.Println(token)
	fmt.Println()
	fmt.Println("=== Token Info ===")
	printTokenInfo()
}

func generateToken() (string, error) {
	// Load private key
	privateKey, err := loadPrivateKey(*privateKeyFile)
	if err != nil {
		return "", fmt.Errorf("failed to load private key: %w", err)
	}

	// Create claims
	now := time.Now()
	var expTime time.Time
	if *expired {
		expTime = now.Add(-1 * time.Hour) // Expired 1 hour ago
	} else {
		expTime = now.Add(*expiry)
	}

	claims := jwt.MapClaims{
		"iss":   *issuer,
		"aud":   *audience,
		"sub":   *subject,
		"email": *email,
		"role":  *role,
		"exp":   expTime.Unix(),
		"iat":   now.Unix(),
		"nbf":   now.Unix(),
	}

	// Add scopes if provided
	if *scopes != "" {
		claims["scope"] = *scopes
	}

	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = *kid

	// Sign token
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

func loadPrivateKey(filename string) (*rsa.PrivateKey, error) {
	keyData, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8 format
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		var ok bool
		privateKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("not an RSA private key")
		}
	}

	return privateKey, nil
}

func generateKeyPair() error {
	fmt.Println("Generating RSA key pair (2048 bits)...")

	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// Save private key
	privateKeyFile := "test-private.pem"
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})
	if err := os.WriteFile(privateKeyFile, privateKeyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}
	fmt.Printf("✓ Private key saved to: %s\n", privateKeyFile)

	// Save public key
	publicKeyFile := "test-public.pem"
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})
	if err := os.WriteFile(publicKeyFile, publicKeyPEM, 0644); err != nil {
		return fmt.Errorf("failed to write public key: %w", err)
	}
	fmt.Printf("✓ Public key saved to: %s\n", publicKeyFile)

	fmt.Println()
	fmt.Println("Use the private key to generate tokens:")
	fmt.Println("  go run generate-token.go -key test-private.pem")
	fmt.Println()
	fmt.Println("Use the public key in your policy configuration:")
	fmt.Println("  publicKey: $(cat test-public.pem)")

	return nil
}

func printTokenInfo() {
	fmt.Println("Issuer (iss):", *issuer)
	fmt.Println("Audience (aud):", *audience)
	fmt.Println("Subject (sub):", *subject)
	fmt.Println("Email:", *email)
	fmt.Println("Role:", *role)
	fmt.Println("Scopes:", *scopes)

	if *expired {
		fmt.Println("Expiry: 1 hour ago (EXPIRED)")
	} else {
		fmt.Printf("Expiry: %v from now\n", *expiry)
	}

	fmt.Println()
	fmt.Println("=== Test Command ===")
	token, _ := generateToken()
	fmt.Printf("curl -H \"Authorization: Bearer %s\" http://localhost:8080/api/resource\n", token)
}

func init() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "JWT Token Generator for Testing\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  Generate RSA key pair:\n")
		fmt.Fprintf(os.Stderr, "    go run generate-token.go -generate-keys\n\n")
		fmt.Fprintf(os.Stderr, "  Generate valid token:\n")
		fmt.Fprintf(os.Stderr, "    go run generate-token.go -key test-private.pem\n\n")
		fmt.Fprintf(os.Stderr, "  Generate expired token:\n")
		fmt.Fprintf(os.Stderr, "    go run generate-token.go -expired\n\n")
		fmt.Fprintf(os.Stderr, "  Custom claims:\n")
		fmt.Fprintf(os.Stderr, "    go run generate-token.go -iss https://myauth.com -sub user456 -role user\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
	}
}
