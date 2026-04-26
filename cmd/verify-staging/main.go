// Package main provides a staging verification tool for the ACME relay.
// It tests the relay → LE staging → AliDNS chain end-to-end.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"

	"acme-relay/internal/acme"
	"acme-relay/internal/dns"
	"acme-relay/internal/storage"
)

func main() {
	domain := flag.String("domain", "", "Domain to request certificate for (must be managed in AliDNS)")
	flag.Parse()

	if *domain == "" {
		log.Fatal("-domain flag is required")
	}

	accessKey := os.Getenv("ALIDNS_ACCESS_KEY")
	secretKey := os.Getenv("ALIDNS_SECRET_KEY")
	if accessKey == "" || secretKey == "" {
		log.Fatal("ALIDNS_ACCESS_KEY and ALIDNS_SECRET_KEY environment variables are required")
	}

	// Create temp storage
	tmpDir, err := os.MkdirTemp("", "acme-relay-verify-*")
	if err != nil {
		log.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	store, err := storage.NewFilesystemStorage(tmpDir)
	if err != nil {
		log.Fatalf("Failed to create storage: %v", err)
	}

	// Create DNS provider
	dnsProvider, err := dns.NewAliDNSProvider(accessKey, secretKey, "cn-hangzhou")
	if err != nil {
		log.Fatalf("Failed to create DNS provider: %v", err)
	}

	// Create relay with LE staging
	stagingURL := "https://acme-staging-v02.api.letsencrypt.org/directory"
	relay, err := acme.NewRelay("acme-relay-verify@test.com", stagingURL, dnsProvider, store)
	if err != nil {
		log.Fatalf("Failed to create relay: %v", err)
	}

	// Generate CSR for the test domain
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: *domain,
		},
		DNSNames: []string{*domain},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	if err != nil {
		log.Fatalf("Failed to create CSR: %v", err)
	}

	csrBase64 := base64.StdEncoding.EncodeToString(csrDER)

	// Request certificate via DNS-01
	fmt.Printf("Requesting certificate for %s via LE staging + AliDNS...\n", *domain)
	resp, err := relay.CompleteCertificateRequest(context.Background(), []string{*domain}, csrBase64)
	if err != nil {
		log.Fatalf("Certificate request failed: %v", err)
	}

	fmt.Println("SUCCESS! Certificate obtained.")
	fmt.Printf("  Domain:    %s\n", *domain)
	fmt.Printf("  Expires:   %s\n", resp.Expires)
	fmt.Printf("  Cert len:  %d bytes\n", len(resp.Certificate))
	fmt.Printf("  Chain len: %d bytes\n", len(resp.Chain))
}
