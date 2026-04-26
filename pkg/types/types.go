// Package types defines shared data structures for acme-relay.
package types

import "time"

// CertificateRequest represents a request for a new certificate.
type CertificateRequest struct {
	Domains []string `json:"domains" validate:"required,min=1"`
	CSR     string   `json:"csr" validate:"required"`
}

// CertificateResponse represents the response containing certificate data.
type CertificateResponse struct {
	Certificate string `json:"certificate"`
	Chain       string `json:"chain"`
	Expires     string `json:"expires"`
}

// Challenge represents an ACME challenge.
type Challenge struct {
	Type      string `json:"type"`
	Token     string `json:"token"`
	URI       string `json:"uri"`
	KeyAuth   string `json:"keyAuthorization,omitempty"`
	Domain    string `json:"domain"`
	Status    string `json:"status"`
}

// ChallengeResponse is returned to the client during HTTP-01 flow.
type ChallengeResponse struct {
	Token     string `json:"token"`
	URI       string `json:"uri"`
	KeyAuth   string `json:"keyAuthorization"`
	Domain    string `json:"domain"`
	ExpiresAt int64  `json:"expiresAt"`
}

// RenewRequest represents a renewal request.
type RenewRequest struct {
	Domain string `json:"domain"`
}

// ErrorResponse represents an API error.
type ErrorResponse struct {
	Error   string `json:"error"`
	Code    int    `json:"code"`
	Details string `json:"details,omitempty"`
}

// HealthResponse represents the health check response.
type HealthResponse struct {
	Status    string `json:"status"`
	Timestamp int64  `json:"timestamp"`
}

// Certificate represents stored certificate metadata.
type Certificate struct {
	Domain        string    `json:"domain"`
	Certificate   string    `json:"certificate"`
	Chain         string    `json:"chain"`
	ExpiresAt     time.Time `json:"expiresAt"`
	IssuedAt      time.Time `json:"issuedAt"`
	SerialNumber  string    `json:"serialNumber,omitempty"`
	RenewalWindow time.Time `json:"renewalWindow,omitempty"`
}

// NewCertificate creates a new Certificate with proper defaults.
func NewCertificate(domain, cert, chain string, expiresAt time.Time) Certificate {
	return Certificate{
		Domain:        domain,
		Certificate:   cert,
		Chain:         chain,
		ExpiresAt:     expiresAt,
		IssuedAt:      time.Now(),
		RenewalWindow: expiresAt.AddDate(0, -1, 0), // 30 days before expiry
	}
}

// IsExpiringSoon returns true if the certificate is within renewal window.
func (c Certificate) IsExpiringSoon() bool {
	return time.Now().After(c.RenewalWindow)
}
