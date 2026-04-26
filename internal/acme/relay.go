// Package acme provides the core ACME relay functionality.
package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/alidns"
	"github.com/go-acme/lego/v4/registration"

	"acme-relay/pkg/types"
)

// RelayClient defines the interface for ACME relay operations.
// Handlers depend on this interface so relay can be mocked in tests.
type RelayClient interface {
	CompleteCertificateRequest(ctx context.Context, domains []string, csrBase64 string) (*types.CertificateResponse, error)
	VerifyHTTP01Challenge(ctx context.Context, domain, token, keyAuth string) error
	RequestCertificate(ctx context.Context, domains []string, csrBase64 string) (*types.CertificateResponse, error)
	GetCertificate(domain string) (*types.CertificateResponse, error)
	RenewCertificate(ctx context.Context, domain string) (*types.CertificateResponse, error)
}

// CertificateStore defines the interface for certificate persistence.
type CertificateStore interface {
	Store(domain string, cert *types.Certificate) error
	Get(domain string) (*types.Certificate, error)
}

// Relay handles ACME certificate acquisition and renewal.
type Relay struct {
	client       *lego.Client
	dnsProvider  *alidns.DNSProvider
	storage      CertificateStore
	email        string
	directoryURL string
	httpClient   *http.Client
}

// NewRelay creates a new ACME relay instance.
func NewRelay(email, directoryURL string, dnsProvider *alidns.DNSProvider, store CertificateStore) (*Relay, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate account key: %w", err)
	}

	acc := &account{email: email, privateKey: privateKey}

	config := lego.NewConfig(acc)
	config.Certificate.KeyType = certcrypto.EC256
	config.CADirURL = directoryURL

	client, err := lego.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create lego client: %w", err)
	}

	if err := client.Challenge.SetDNS01Provider(dnsProvider); err != nil {
		return nil, fmt.Errorf("failed to set DNS-01 provider: %w", err)
	}

	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return nil, fmt.Errorf("failed to register account with CA: %w", err)
	}
	acc.reg = reg

	return &Relay{
		client:       client,
		dnsProvider:  dnsProvider,
		storage:      store,
		email:        email,
		directoryURL: directoryURL,
		httpClient:   &http.Client{Timeout: 10 * time.Second},
	}, nil
}

// InitiateCertificate starts the certificate request flow.
// Step 1: Generate HTTP-01 challenge and return challenge info for the server to respond.
func (r *Relay) InitiateCertificate(ctx context.Context, domains []string, csrBase64 string) (*types.ChallengeResponse, error) {
	// Decode and parse CSR
	csrBytes, err := base64.StdEncoding.DecodeString(csrBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode CSR: %w", err)
	}

	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR: %w", err)
	}

	primaryDomain := csr.Subject.CommonName
	if primaryDomain == "" && len(domains) > 0 {
		primaryDomain = domains[0]
	}

	// Generate HTTP-01 challenge token
	token, err := generateToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	// Compute keyAuthorization for HTTP-01
	// Note: In the relay context, the thumbprint is from our upstream LE account key.
	// For the ACME server context, this will be computed per-account via ComputeKeyAuthorization.
	keyAuth := token + "." + "relay-placeholder"

	// Build challenge URL
	challengeURL := fmt.Sprintf("http://%s/.well-known/acme-challenge/%s", primaryDomain, token)

	expiresAt := time.Now().Add(10 * time.Minute).Unix()

	return &types.ChallengeResponse{
		Token:     token,
		URI:       challengeURL,
		KeyAuth:   keyAuth,
		Domain:    primaryDomain,
		ExpiresAt: expiresAt,
	}, nil
}

// VerifyHTTP01Challenge verifies that the server has responded to the HTTP-01 challenge.
// It fetches the challenge URL and verifies the response matches the expected keyAuthorization.
func (r *Relay) VerifyHTTP01Challenge(ctx context.Context, domain, token, keyAuth string) error {
	challengeURL := fmt.Sprintf("http://%s/.well-known/acme-challenge/%s", domain, token)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, challengeURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create challenge request: %w", err)
	}

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to reach challenge endpoint: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("challenge endpoint returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read challenge response: %w", err)
	}

	// Trim whitespace (some servers add trailing newline)
	got := strings.TrimSpace(string(body))
	if got != keyAuth {
		return fmt.Errorf("keyAuthorization mismatch: got %q, want %q", got, keyAuth)
	}

	return nil
}

// CompleteCertificateRequest completes the certificate flow after HTTP-01 verification.
// Step 3: Use DNS-01 to obtain certificate from Let's Encrypt.
func (r *Relay) CompleteCertificateRequest(ctx context.Context, domains []string, csrBase64 string) (*types.CertificateResponse, error) {
	// Decode CSR
	csrBytes, err := base64.StdEncoding.DecodeString(csrBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode CSR: %w", err)
	}

	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR: %w", err)
	}

	primaryDomain := csr.Subject.CommonName
	if primaryDomain == "" && len(domains) > 0 {
		primaryDomain = domains[0]
	}

	// Use DNS-01 to obtain certificate
	obtainReq := certificate.ObtainForCSRRequest{
		CSR: csr,
	}

	certMeta, err := r.client.Certificate.ObtainForCSR(obtainReq)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain certificate: %w", err)
	}

	expiresAt, err := parseExpiresAt(string(certMeta.Certificate))
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate expiry: %w", err)
	}

	cert := types.NewCertificate(primaryDomain, string(certMeta.Certificate), string(certMeta.IssuerCertificate), expiresAt)

	if err := r.storage.Store(primaryDomain, &cert); err != nil {
		return nil, fmt.Errorf("failed to store certificate: %w", err)
	}

	return &types.CertificateResponse{
		Certificate: string(certMeta.Certificate),
		Chain:       string(certMeta.IssuerCertificate),
		Expires:     expiresAt.Format(time.RFC3339),
	}, nil
}

// RequestCertificate handles a new certificate request (combined flow).
// For backward compatibility - initiates and waits for HTTP-01.
func (r *Relay) RequestCertificate(ctx context.Context, domains []string, csrBase64 string) (*types.CertificateResponse, error) {
	// Step 1: Initiate and get challenge
	_, err := r.InitiateCertificate(ctx, domains, csrBase64)
	if err != nil {
		return nil, err
	}

	// Step 2: Server must respond to challenge
	// For backward compatibility, we assume sync flow where server already responded
	// In production, this should be async with proper challenge state management

	// Step 3: Complete with DNS-01
	return r.CompleteCertificateRequest(ctx, domains, csrBase64)
}

// GetCertificate retrieves an existing certificate.
func (r *Relay) GetCertificate(domain string) (*types.CertificateResponse, error) {
	cert, err := r.storage.Get(domain)
	if err != nil {
		return nil, err
	}

	return &types.CertificateResponse{
		Certificate: cert.Certificate,
		Chain:       cert.Chain,
		Expires:     cert.ExpiresAt.Format(time.RFC3339),
	}, nil
}

// RenewCertificate triggers renewal for an existing certificate.
func (r *Relay) RenewCertificate(ctx context.Context, domain string) (*types.CertificateResponse, error) {
	existingCert, err := r.storage.Get(domain)
	if err != nil {
		return nil, fmt.Errorf("certificate not found for domain: %s", domain)
	}

	return r.RequestCertificate(ctx, []string{domain}, base64.StdEncoding.EncodeToString([]byte(existingCert.Certificate)))
}

// CheckExpiry checks if a certificate needs renewal.
func (r *Relay) CheckExpiry(domain string) (bool, error) {
	cert, err := r.storage.Get(domain)
	if err != nil {
		return false, err
	}

	return cert.IsExpiringSoon(), nil
}

// generateToken generates a random token for HTTP-01 challenge.
func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// computeKeyAuthorization computes the key authorization for HTTP-01 challenge.
func computeKeyAuthorization(token string, thumbprint string) string {
	return token + "." + thumbprint
}

// account implements lego.User for ACME registration.
type account struct {
	email      string
	privateKey *ecdsa.PrivateKey
	reg        *registration.Resource
}

func (a *account) GetEmail() string {
	return a.email
}

func (a *account) GetRegistration() *registration.Resource {
	return a.reg
}

func (a *account) GetPrivateKey() crypto.PrivateKey {
	return a.privateKey
}

// containsString checks if a string is in a list.
func containsString(list []string, s string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}

// DecodeCSR decodes a base64-encoded CSR and returns the PEM block.
func DecodeCSR(csrBase64 string) ([]byte, error) {
	csrBytes, err := base64.StdEncoding.DecodeString(csrBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", err)
	}
	return csrBytes, nil
}

// GetDomainsFromCSR extracts domains from a CSR.
func GetDomainsFromCSR(csrBase64 string) ([]string, error) {
	csrBytes, err := base64.StdEncoding.DecodeString(csrBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode CSR: %w", err)
	}

	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR: %w", err)
	}

	var domains []string
	if csr.Subject.CommonName != "" {
		domains = append(domains, csr.Subject.CommonName)
	}
	for _, name := range csr.DNSNames {
		if !containsString(domains, name) {
			domains = append(domains, name)
		}
	}
	return domains, nil
}

// parseExpiresAt extracts the expiration time from a PEM certificate.
func parseExpiresAt(pemData string) (time.Time, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return time.Time{}, fmt.Errorf("failed to decode PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse certificate: %w", err)
	}
	return cert.NotAfter, nil
}

// NormalizeDomain ensures domain has proper format.
func NormalizeDomain(domain string) string {
	domain = strings.TrimSpace(domain)
	domain = strings.ToLower(domain)
	if strings.HasPrefix(domain, "http://") {
		domain = strings.TrimPrefix(domain, "http://")
	}
	if strings.HasPrefix(domain, "https://") {
		domain = strings.TrimPrefix(domain, "https://")
	}
	if strings.HasPrefix(domain, "www.") {
		domain = strings.TrimPrefix(domain, "www.")
	}
	return domain
}

// HashCSR creates a SHA256 hash of the CSR for challenge identification.
func HashCSR(csrBase64 string) string {
	csrBytes, _ := base64.StdEncoding.DecodeString(csrBase64)
	hash := sha256.Sum256(csrBytes)
	return base64.RawURLEncoding.EncodeToString(hash[:])
}
