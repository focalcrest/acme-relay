package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestHashCSR(t *testing.T) {
	// Empty/invalid base64 should still return something (no panic)
	result := HashCSR("invalid")
	if result == "" {
		t.Error("HashCSR should return non-empty string")
	}

	// Valid base64 but invalid CSR content
	result2 := HashCSR("dGVzdA==") // "test" in base64
	if result2 == "" {
		t.Error("HashCSR should return non-empty for valid base64")
	}

	// Same input produces same hash
	result3 := HashCSR("dGVzdA==")
	if result2 != result3 {
		t.Error("same input should produce same hash")
	}
}

func TestParseExpiresAt(t *testing.T) {
	_, err := parseExpiresAt("not-pem")
	if err == nil {
		t.Error("expected error for non-PEM input")
	}

	_, err = parseExpiresAt("-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----")
	if err == nil {
		t.Error("expected error for invalid PEM certificate")
	}
}

func TestComputeKeyAuthorizationRelay(t *testing.T) {
	result := computeKeyAuthorization("mytoken", "mythumb")
	if result != "mytoken.mythumb" {
		t.Errorf("computeKeyAuthorization = %q, want mytoken.mythumb", result)
	}
}

func TestAccountGetters(t *testing.T) {
	a := &account{email: "test@example.com"}
	if a.GetEmail() != "test@example.com" {
		t.Errorf("GetEmail() = %q, want test@example.com", a.GetEmail())
	}
	if a.GetRegistration() != nil {
		t.Error("GetRegistration() should return nil")
	}
	// GetPrivateKey returns nil *ecdsa.PrivateKey as crypto.PrivateKey interface,
	// which is non-nil. This is expected Go behavior with nil typed pointers.
}

func TestDecodeCSR_Valid(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "test.example.com"},
		DNSNames: []string{"test.example.com"},
	}
	der, _ := x509.CreateCertificateRequest(rand.Reader, template, key)
	b64 := base64.StdEncoding.EncodeToString(der)

	decoded, err := DecodeCSR(b64)
	if err != nil {
		t.Fatalf("DecodeCSR() error = %v", err)
	}
	if len(decoded) == 0 {
		t.Error("DecodeCSR() returned empty bytes")
	}
}

func TestGetDomainsFromCSR_Valid(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	t.Run("common name only", func(t *testing.T) {
		template := &x509.CertificateRequest{
			Subject: pkix.Name{CommonName: "cn.example.com"},
		}
		der, _ := x509.CreateCertificateRequest(rand.Reader, template, key)
		b64 := base64.StdEncoding.EncodeToString(der)

		domains, err := GetDomainsFromCSR(b64)
		if err != nil {
			t.Fatalf("GetDomainsFromCSR() error = %v", err)
		}
		if len(domains) != 1 || domains[0] != "cn.example.com" {
			t.Errorf("domains = %v, want [cn.example.com]", domains)
		}
	})

	t.Run("SANs with dedup", func(t *testing.T) {
		template := &x509.CertificateRequest{
			Subject:  pkix.Name{CommonName: "example.com"},
			DNSNames: []string{"example.com", "www.example.com"},
		}
		der, _ := x509.CreateCertificateRequest(rand.Reader, template, key)
		b64 := base64.StdEncoding.EncodeToString(der)

		domains, err := GetDomainsFromCSR(b64)
		if err != nil {
			t.Fatalf("GetDomainsFromCSR() error = %v", err)
		}
		if len(domains) != 2 {
			t.Errorf("domains = %v, want 2 unique entries", domains)
		}
	})

	t.Run("SANs without common name", func(t *testing.T) {
		template := &x509.CertificateRequest{
			DNSNames: []string{"san.example.com"},
		}
		der, _ := x509.CreateCertificateRequest(rand.Reader, template, key)
		b64 := base64.StdEncoding.EncodeToString(der)

		domains, err := GetDomainsFromCSR(b64)
		if err != nil {
			t.Fatalf("GetDomainsFromCSR() error = %v", err)
		}
		if len(domains) != 1 || domains[0] != "san.example.com" {
			t.Errorf("domains = %v, want [san.example.com]", domains)
		}
	})

	t.Run("invalid DER", func(t *testing.T) {
		b64 := base64.StdEncoding.EncodeToString([]byte("garbage"))
		_, err := GetDomainsFromCSR(b64)
		if err == nil {
			t.Error("expected error for invalid DER, got nil")
		}
	})
}

func TestParseExpiresAt_ValidCert(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	pemData := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))

	expiresAt, err := parseExpiresAt(pemData)
	if err != nil {
		t.Fatalf("parseExpiresAt() error = %v", err)
	}
	if expiresAt.Before(time.Now()) {
		t.Errorf("expiresAt = %v, should be in the future", expiresAt)
	}
}
