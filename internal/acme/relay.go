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
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/miekg/dns"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"

	"github.com/focalcrest/acme-relay/pkg/types"
)

// RelayClient defines the interface for ACME relay operations.
// Handlers depend on this interface so relay can be mocked in tests.
type RelayClient interface {
	CompleteCertificateRequest(ctx context.Context, domains []string, csrBase64 string) (*types.CertificateResponse, error)
	VerifyHTTP01Challenge(ctx context.Context, domain, token, keyAuth string) error
	VerifyDNS01Challenge(ctx context.Context, domain, token, keyAuth string) error
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
	client               *lego.Client
	dnsProvider          challenge.Provider
	storage              CertificateStore
	email                string
	directoryURL         string
	httpClient           *http.Client
	jwkThumbprint        string
	recursiveNameservers []string
}

// NewRelay creates a new ACME relay instance. recursiveNameservers, when
// non-empty, is used to query DNS-01 TXT records directly (needed for
// split-horizon setups where the relay's own resolver disagrees with the
// public view); when empty, the system resolver is used instead.
func NewRelay(email, directoryURL string, dnsProvider challenge.Provider, store CertificateStore, recursiveNameservers []string) (*Relay, error) {
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

	// Compute JWK thumbprint for HTTP-01 keyAuthorization
	jwk := jose.JSONWebKey{Key: privateKey.Public()}
	thumbprintBytes, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("failed to compute JWK thumbprint: %w", err)
	}
	jwkThumbprint := base64.RawURLEncoding.EncodeToString(thumbprintBytes)

	return &Relay{
		client:               client,
		dnsProvider:          dnsProvider,
		storage:              store,
		email:                email,
		directoryURL:         directoryURL,
		httpClient:           &http.Client{Timeout: 10 * time.Second},
		jwkThumbprint:        jwkThumbprint,
		recursiveNameservers: dns01.ParseNameservers(recursiveNameservers),
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

	// Compute keyAuthorization for HTTP-01 using the relay's JWK thumbprint
	keyAuth := computeKeyAuthorization(token, r.jwkThumbprint)

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

// VerifyDNS01Challenge verifies that the client has published the expected
// DNS-01 key authorization digest at _acme-challenge.<domain>. Unlike the
// DNS TXT API (which just writes records on request), this does a real DNS
// lookup, mirroring how a public CA would validate the challenge.
func (r *Relay) VerifyDNS01Challenge(ctx context.Context, domain, _, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	values, err := r.lookupTXT(ctx, info.FQDN)
	if err != nil {
		return fmt.Errorf("failed to query DNS-01 TXT record for %s: %w", info.FQDN, err)
	}

	if !containsString(values, info.Value) {
		return fmt.Errorf("TXT record for %s does not contain expected key authorization digest", info.FQDN)
	}

	return nil
}

// lookupTXT queries a TXT record. When recursiveNameservers is configured it
// queries them directly with miekg/dns (needed for split-horizon DNS where
// the relay's default resolver would return an internal, non-public
// answer); otherwise it falls back to the system resolver.
func (r *Relay) lookupTXT(ctx context.Context, fqdn string) ([]string, error) {
	if len(r.recursiveNameservers) == 0 {
		return net.DefaultResolver.LookupTXT(ctx, fqdn)
	}

	m := new(dns.Msg)
	m.SetQuestion(fqdn, dns.TypeTXT)
	m.RecursionDesired = true

	client := &dns.Client{Timeout: 10 * time.Second}

	var lastErr error
	for _, ns := range r.recursiveNameservers {
		resp, _, err := client.ExchangeContext(ctx, m, ns)
		if err != nil {
			lastErr = fmt.Errorf("nameserver %s: %w", ns, err)
			continue
		}
		if resp.Rcode != dns.RcodeSuccess {
			lastErr = fmt.Errorf("nameserver %s returned %s", ns, dns.RcodeToString[resp.Rcode])
			continue
		}

		var values []string
		for _, rr := range resp.Answer {
			if txt, ok := rr.(*dns.TXT); ok {
				values = append(values, strings.Join(txt.Txt, ""))
			}
		}
		return values, nil
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("no recursive nameservers available")
	}
	return nil, lastErr
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
	_, err := r.storage.Get(domain)
	if err != nil {
		return nil, fmt.Errorf("certificate not found for domain: %s", domain)
	}

	// Generate a fresh key and CSR for renewal
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate renewal key: %w", err)
	}

	template := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domain},
		DNSNames: []string{domain},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create renewal CSR: %w", err)
	}

	csrBase64 := base64.StdEncoding.EncodeToString(csrDER)
	return r.CompleteCertificateRequest(ctx, []string{domain}, csrBase64)
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
