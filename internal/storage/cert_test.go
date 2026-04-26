package storage

import (
	"testing"
	"time"

	"acme-relay/pkg/types"
)

func TestFilesystemStorage_StoreAndGetCertificate(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewFilesystemStorage(dir)

	cert := &types.Certificate{
		Domain:      "example.com",
		Certificate: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
		Chain:       "-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----",
		ExpiresAt:   time.Now().Add(90 * 24 * time.Hour),
		IssuedAt:    time.Now(),
	}

	if err := store.Store("example.com", cert); err != nil {
		t.Fatalf("Store() error: %v", err)
	}

	got, err := store.Get("example.com")
	if err != nil {
		t.Fatalf("Get() error: %v", err)
	}
	if got.Domain != "example.com" {
		t.Errorf("Domain = %q, want example.com", got.Domain)
	}
	if got.Certificate != cert.Certificate {
		t.Error("Certificate data mismatch")
	}
}

func TestFilesystemStorage_Get_NotFound(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewFilesystemStorage(dir)

	_, err := store.Get("nonexistent.com")
	if err == nil {
		t.Error("expected error for non-existent certificate")
	}
}

func TestFilesystemStorage_Exists(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewFilesystemStorage(dir)

	if store.Exists("example.com") {
		t.Error("Exists should return false for non-existent cert")
	}

	cert := &types.Certificate{
		Domain:        "example.com",
		Certificate:   "cert-data",
		ExpiresAt:     time.Now().Add(90 * 24 * time.Hour),
		IssuedAt:      time.Now(),
	}
	store.Store("example.com", cert)

	if !store.Exists("example.com") {
		t.Error("Exists should return true for stored cert")
	}
}

func TestFilesystemStorage_Delete(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewFilesystemStorage(dir)

	cert := &types.Certificate{
		Domain:        "example.com",
		Certificate:   "cert-data",
		ExpiresAt:     time.Now().Add(90 * 24 * time.Hour),
		IssuedAt:      time.Now(),
	}
	store.Store("example.com", cert)

	if err := store.Delete("example.com"); err != nil {
		t.Fatalf("Delete() error: %v", err)
	}

	if store.Exists("example.com") {
		t.Error("cert should not exist after delete")
	}

	// Deleting non-existent should not error
	if err := store.Delete("nonexistent.com"); err != nil {
		t.Fatalf("Delete() non-existent error: %v", err)
	}
}

func TestFilesystemStorage_List(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewFilesystemStorage(dir)

	cert := &types.Certificate{
		Certificate: "cert-data",
		ExpiresAt:   time.Now().Add(90 * 24 * time.Hour),
		IssuedAt:    time.Now(),
	}
	store.Store("a.com", cert)
	store.Store("b.com", cert)

	domains, err := store.List()
	if err != nil {
		t.Fatalf("List() error: %v", err)
	}
	if len(domains) != 2 {
		t.Errorf("List() returned %d domains, want 2", len(domains))
	}
}

func TestParseExpiresAt(t *testing.T) {
	_, err := ParseExpiresAt("not-pem")
	if err == nil {
		t.Error("expected error for non-PEM input")
	}

	_, err = ParseExpiresAt("-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----")
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
}
