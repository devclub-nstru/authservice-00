package oidc

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/google/uuid"
)

// IDTokenClaims represents the claims embedded in a signed ID token.
type IDTokenClaims struct {
	Iss           string  `json:"iss"`
	Sub           string  `json:"sub"`
	Aud           string  `json:"aud"`
	Exp           int64   `json:"exp"`
	Iat           int64   `json:"iat"`
	Nonce         string  `json:"nonce,omitempty"`
	Email         string  `json:"email,omitempty"`
	EmailVerified bool    `json:"email_verified,omitempty"`
	Name          *string `json:"name,omitempty"`
	Picture       *string `json:"picture,omitempty"`
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid,omitempty"`
}

// RSAKeyPair holds a private key alongside a stable key ID used in JWKS.
type RSAKeyPair struct {
	PrivateKey *rsa.PrivateKey
	KeyID      string
}

// GenerateRSAKeyPair creates a new 2048-bit RSA key pair with a random KID.
func GenerateRSAKeyPair() (*RSAKeyPair, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}
	kid, err := randomKID()
	if err != nil {
		return nil, err
	}
	return &RSAKeyPair{PrivateKey: priv, KeyID: kid}, nil
}

// SignIDTokenRS256 signs an ID token with RS256 using the provided key pair.
func SignIDTokenRS256(kp *RSAKeyPair, claims IDTokenClaims) (string, error) {
	header := jwtHeader{Alg: "RS256", Typ: "JWT", Kid: kp.KeyID}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	headerEncoded := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsEncoded := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := headerEncoded + "." + claimsEncoded

	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, kp.PrivateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// JWK represents a single JSON Web Key.
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKSDocument is the JSON Web Key Set served at /jwks.json.
type JWKSDocument struct {
	Keys []JWK `json:"keys"`
}

// BuildJWKS converts an RSA public key into a JWKS document.
func BuildJWKS(kp *RSAKeyPair) *JWKSDocument {
	pub := &kp.PrivateKey.PublicKey

	// Encode modulus and exponent in base64url (big-endian, no padding)
	nBytes := pub.N.Bytes()
	eBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(eBytes, uint32(pub.E))
	// Trim leading zero bytes from exponent
	eBytes = eBytes[countLeadingZeros(eBytes):]

	return &JWKSDocument{
		Keys: []JWK{
			{
				Kty: "RSA",
				Use: "sig",
				Alg: "RS256",
				Kid: kp.KeyID,
				N:   base64.RawURLEncoding.EncodeToString(nBytes),
				E:   base64.RawURLEncoding.EncodeToString(eBytes),
			},
		},
	}
}

// BuildIDTokenClaims constructs the standard claim set for an ID token.
func BuildIDTokenClaims(issuer string, userID uuid.UUID, clientID string, nonce *string, email string, emailVerified bool, name *string, avatarURL *string, ttl time.Duration) IDTokenClaims {
	now := time.Now()
	claims := IDTokenClaims{
		Iss:           issuer,
		Sub:           userID.String(),
		Aud:           clientID,
		Exp:           now.Add(ttl).Unix(),
		Iat:           now.Unix(),
		Email:         email,
		EmailVerified: emailVerified,
		Name:          name,
		Picture:       avatarURL,
	}
	if nonce != nil {
		claims.Nonce = *nonce
	}
	return claims
}

// ParseIDTokenClaims parses an RS256 JWT and returns its claims without
// verifying the signature (used internally when the key is already trusted).
// For proper verification (e.g. in introspection) we verify via the public key.
func VerifyIDTokenRS256(kp *RSAKeyPair, tokenStr string) (*IDTokenClaims, error) {
	parts, headerEncoded, claimsEncoded, sigEncoded, err := splitJWT(tokenStr)
	_ = parts
	if err != nil {
		return nil, err
	}

	// Verify signature
	signingInput := headerEncoded + "." + claimsEncoded
	digest := sha256.Sum256([]byte(signingInput))
	sigBytes, err := base64.RawURLEncoding.DecodeString(sigEncoded)
	if err != nil {
		return nil, fmt.Errorf("invalid signature encoding")
	}
	if err := rsa.VerifyPKCS1v15(&kp.PrivateKey.PublicKey, crypto.SHA256, digest[:], sigBytes); err != nil {
		return nil, fmt.Errorf("signature verification failed")
	}

	// Decode claims
	claimsJSON, err := base64.RawURLEncoding.DecodeString(claimsEncoded)
	if err != nil {
		return nil, fmt.Errorf("invalid claims encoding")
	}
	var claims IDTokenClaims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, fmt.Errorf("invalid claims JSON")
	}
	return &claims, nil
}

// --- helpers ---

func randomKID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}

func countLeadingZeros(b []byte) int {
	for i, v := range b {
		if v != 0 {
			return i
		}
	}
	return len(b)
}

// LoadRSAKeyPairFromPEM reads an RSA PKCS#1 or PKCS#8 private key from a PEM
// file and derives a stable KID from the public key's modulus so that the same
// kid is advertised in JWKS on every restart.
func LoadRSAKeyPairFromPEM(path string) (*RSAKeyPair, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read OIDC private key at %q: %w", path, err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %q", path)
	}

	var priv *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		priv, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("invalid PKCS#1 key: %w", err)
		}
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("invalid PKCS#8 key: %w", err)
		}
		var ok bool
		priv, ok = key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PKCS#8 key is not RSA")
		}
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q", block.Type)
	}

	// Derive a stable kid from the public modulus so it never changes between restarts.
	h := sha256.Sum256(priv.PublicKey.N.Bytes())
	kid := base64.RawURLEncoding.EncodeToString(h[:8]) // short but unique

	return &RSAKeyPair{PrivateKey: priv, KeyID: kid}, nil
}

func splitJWT(token string) (parts []string, header, claims, sig string, err error) {
	// manual split to avoid importing strings at this layer
	start, dot1, dot2 := 0, -1, -1
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			if dot1 == -1 {
				dot1 = i
			} else if dot2 == -1 {
				dot2 = i
				break
			}
		}
	}
	if dot1 == -1 || dot2 == -1 {
		return nil, "", "", "", fmt.Errorf("malformed JWT")
	}
	_ = start
	_ = big.NewInt // keep math/big import satisfied (used only via pub.N.Bytes())
	header = token[:dot1]
	claims = token[dot1+1 : dot2]
	sig = token[dot2+1:]
	return []string{header, claims, sig}, header, claims, sig, nil
}
