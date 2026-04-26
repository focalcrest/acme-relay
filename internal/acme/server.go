// Package acme provides ACME server implementation.
package acme

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"time"
)

// Directory URLs
type Directory struct {
	NewNonce   string `json:"newNonce"`
	NewAccount string `json:"newAccount"`
	NewOrder   string `json:"newOrder"`
	RevokeCert string `json:"revokeCert"`
	KeyChange  string `json:"keyChange"`
}

// Identifier represents a certificate identifier
type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Order represents an ACME order
type Order struct {
	ID            int64      `json:"id"`
	Status        string     `json:"status"`
	Identifiers   []Identifier `json:"identifiers"`
	Authorizations []string   `json:"authorizations"`
	Finalize      string     `json:"finalize"`
	Certificate   string     `json:"certificate,omitempty"`
	NotBefore     time.Time  `json:"notBefore,omitempty"`
	NotAfter      time.Time  `json:"notAfter,omitempty"`
	CreatedAt     time.Time  `json:"createdAt"`
	AccountID     int64      `json:"accountId"`
	CSR           string     `json:"csr,omitempty"`
}

// Authorization represents an ACME authorization
type Authorization struct {
	ID         int64       `json:"id"`
	Status     string      `json:"status"`
	Identifier Identifier  `json:"identifier"`
	Challenges []Challenge `json:"challenges"`
	Wildcard   bool        `json:"wildcard,omitempty"`
	ExpiresAt  time.Time   `json:"expiresAt"`
	AccountID  int64       `json:"accountId"`
}

// Challenge represents an ACME challenge
type Challenge struct {
	Type        string     `json:"type"`
	URL         string     `json:"url"`
	Token       string     `json:"token"`
	Status      string     `json:"status"`
	KeyAuth     string     `json:"keyAuthorization,omitempty"`
	Validated   time.Time  `json:"validated,omitempty"`
	Error       *Problem   `json:"error,omitempty"`
}

// Account represents an ACME account
type Account struct {
	ID        int64     `json:"id"`
	Status    string    `json:"status"`
	Email     string    `json:"email,omitempty"`
	OrdersURL string    `json:"orders"`
	PublicKey string    `json:"publicKey,omitempty"`
	JWKJSON   string    `json:"jwkJson,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
}

// Account create request
type AccountCreateRequest struct {
	TermsOfServiceAgreed bool   `json:"termsOfServiceAgreed"`
	Email               string `json:"email,omitempty"`
}

// Order create request
type OrderCreateRequest struct {
	Identifiers []Identifier `json:"identifiers"`
	NotBefore   string       `json:"notBefore,omitempty"`
	NotAfter    string       `json:"notAfter,omitempty"`
}

// Authorization create request (legacy, not in RFC 8555 but some clients use it)
type AuthzCreateRequest struct {
	Identifier Identifier `json:"identifier"`
}

// CSR Request
type FinalizeRequest struct {
	CSR string `json:"csr"`
}

// Revoke Request
type RevokeRequest struct {
	Certificate string `json:"certificate"`
	Reason      int    `json:"reason,omitempty"`
}

// Challenge update request (for POST to challenge URL)
type ChallengeUpdate struct {
}

// Problem represents an ACME problem (RFC 7807)
type Problem struct {
	Type       string `json:"type"`
	Title      string `json:"title,omitempty"`
	Detail     string `json:"detail,omitempty"`
	Status     int    `json:"status,omitempty"`
	Instance   string `json:"instance,omitempty"`
}

// Error implements the error interface
func (p *Problem) Error() string {
	if p.Detail != "" {
		return p.Detail
	}
	return p.Type
}

// Nonce response
type NonceResponse struct {
	Nonce string `json:"nonce"`
}

// NewDirectory creates a new ACME directory
func NewDirectory(baseURL string) Directory {
	return Directory{
		NewNonce:   baseURL + "/acme/newnonce",
		NewAccount: baseURL + "/acme/new-account",
		NewOrder:   baseURL + "/acme/new-order",
		RevokeCert: baseURL + "/acme/revoke-cert",
		KeyChange:  baseURL + "/acme/key-change",
	}
}

// GenerateNonce generates a new nonce
func GenerateNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// GenerateToken generates a challenge token
func GenerateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ComputeKeyAuthorization computes key authorization for HTTP-01 challenge
func ComputeKeyAuthorization(token string, accountKeyThumbprint string) string {
	return token + "." + accountKeyThumbprint
}

// ComputeDNSKeyAuthorization computes key authorization for DNS-01 challenge
func ComputeDNSKeyAuthorization(token string, accountKeyThumbprint string) string {
	return token + "." + accountKeyThumbprint
}

// ComputeThumbprint computes the JWK thumbprint of the account public key
func ComputeThumbprint(publicKey []byte) string {
	hash := sha256.Sum256(publicKey)
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// ParseIdentifiers validates and parses identifiers from order request
func ParseIdentifiers(identifiers []Identifier) ([]Identifier, error) {
	var valid []Identifier
	for _, id := range identifiers {
		if id.Type != "dns" {
			return nil, &Problem{
				Type:   "urn:ietf:params:acme:error:unsupportedIdentifier",
				Detail: fmt.Sprintf("identifier type %s not supported", id.Type),
				Status: 400,
			}
		}
		if !isValidDomain(id.Value) {
			return nil, &Problem{
				Type:   "urn:ietf:params:acme:error:invalidIdentifier",
				Detail: fmt.Sprintf("invalid domain name: %s", id.Value),
				Status: 400,
			}
		}
		valid = append(valid, id)
	}
	return valid, nil
}

// isValidDomain performs basic domain validation
func isValidDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}
	// Basic check: must have at least one dot and no invalid characters
	if !strings.Contains(domain, ".") {
		return false
	}
	// Check for valid characters (alphanumeric, hyphen, dot)
	for _, c := range domain {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-') {
			return false
		}
	}
	return true
}

// OrderStatus constants
const (
	OrderStatusPending    = "pending"
	OrderStatusReady     = "ready"
	OrderStatusProcessing = "processing"
	OrderStatusValid     = "valid"
	OrderStatusInvalid   = "invalid"
)

// AuthorizationStatus constants
const (
	AuthzStatusPending   = "pending"
	AuthzStatusValid     = "valid"
	AuthzStatusInvalid   = "invalid"
	AuthzStatusDeactivated = "deactivated"
	AuthzStatusExpired   = "expired"
	AuthzStatusRevoked   = "revoked"
)

// ChallengeStatus constants
const (
	ChallengeStatusPending    = "pending"
	ChallengeStatusProcessing = "processing"
	ChallengeStatusValid     = "valid"
	ChallengeStatusInvalid   = "invalid"
)

// ChallengeType constants
const (
	ChallengeTypeHTTP01 = "http-01"
	ChallengeTypeDNS01  = "dns-01"
	ChallengeTypeALPN01 = "tls-alpn-01"
)

// AccountStatus constants
const (
	AccountStatusValid = "valid"
	AccountStatusDeactivated = "deactivated"
	AccountStatusRevoked = "revoked"
)
