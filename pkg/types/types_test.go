package types

import (
	"testing"
	"time"
)

func TestNewCertificate(t *testing.T) {
	expiresAt := time.Now().Add(90 * 24 * time.Hour)
	cert := NewCertificate("example.com", "cert-pem", "chain-pem", expiresAt)

	if cert.Domain != "example.com" {
		t.Errorf("Domain = %q, want example.com", cert.Domain)
	}
	if cert.Certificate != "cert-pem" {
		t.Errorf("Certificate not set correctly")
	}
	if cert.Chain != "chain-pem" {
		t.Errorf("Chain not set correctly")
	}
	if cert.IssuedAt.IsZero() {
		t.Error("IssuedAt should be set")
	}
	if cert.RenewalWindow.IsZero() {
		t.Error("RenewalWindow should be set")
	}
	// Renewal window should be ~30 days before expiry
	expectedWindow := expiresAt.AddDate(0, -1, 0)
	if cert.RenewalWindow.Sub(expectedWindow).Abs() > time.Second {
		t.Errorf("RenewalWindow = %v, want ~%v", cert.RenewalWindow, expectedWindow)
	}
}

func TestIsExpiringSoon_False(t *testing.T) {
	cert := NewCertificate("example.com", "cert", "chain", time.Now().Add(365*24*time.Hour))
	if cert.IsExpiringSoon() {
		t.Error("certificate with 1 year to expiry should not be expiring soon")
	}
}

func TestIsExpiringSoon_True(t *testing.T) {
	cert := Certificate{
		Domain:        "example.com",
		ExpiresAt:     time.Now().Add(10 * 24 * time.Hour),
		RenewalWindow: time.Now().Add(-1 * time.Hour), // already past renewal window
	}
	if !cert.IsExpiringSoon() {
		t.Error("certificate past renewal window should be expiring soon")
	}
}
