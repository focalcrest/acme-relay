// Package dns provides AliDNS integration for DNS-01 challenges.
package dns

import (
	"fmt"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/providers/dns/alidns"
)

// AliDNSProvider is an alias for the lego AliDNS provider.
type AliDNSProvider = alidns.DNSProvider

// NewAliDNSProvider creates a new AliDNS provider.
func NewAliDNSProvider(accessKey, secretKey, regionID string) (*alidns.DNSProvider, error) {
	config := alidns.NewDefaultConfig()
	config.APIKey = accessKey
	config.SecretKey = secretKey
	config.RegionID = regionID
	config.HTTPTimeout = 30 * time.Second

	provider, err := alidns.NewDNSProviderConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create AliDNS provider: %w", err)
	}

	return provider, nil
}

// GetChallengeDomain returns the FQDN for the DNS-01 challenge.
func GetChallengeDomain(domain string) string {
	return fmt.Sprintf("_acme-challenge.%s", domain)
}

// ExtractDNSChallenge extracts domain and key authorization from challenge.
func ExtractDNSChallenge(fqdn, token, keyAuth string) (domain, recordValue string, err error) {
	// Parse _acme-challenge.domain.com format
	prefix := "_acme-challenge."
	if !strings.HasPrefix(fqdn, prefix) {
		return "", "", fmt.Errorf("invalid challenge FQDN: %s", fqdn)
	}

	domain = strings.TrimPrefix(fqdn, prefix)
	recordValue = keyAuth

	return domain, recordValue, nil
}
