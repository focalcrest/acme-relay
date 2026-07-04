// Package dns provides DNS provider integration for DNS-01 challenges.
package dns

import (
	"fmt"
	"os"
	"sort"
	"strings"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	alidns "github.com/go-acme/alidns-20150109/v4/client"
)

// TXTRecordManager defines the interface for raw DNS TXT record operations.
// Unlike lego's challenge.Provider (which derives the record value from a
// key authorization), implementations write caller-supplied values, which
// is what the /api/v1/dns/txt endpoints need.
type TXTRecordManager interface {
	AddTXTRecord(fqdn, value string) error
	RemoveTXTRecord(fqdn, value string) error
}

// txtManagerFactory builds a TXTRecordManager that reads its credentials
// from environment variables. The runtime is expected to export
// config.DNS.Credentials into the process environment before calling this,
// mirroring the lego provider registry.
type txtManagerFactory func() (TXTRecordManager, error)

var txtManagerRegistry = map[string]txtManagerFactory{
	"alidns": func() (TXTRecordManager, error) {
		return NewAliDNSTXTManager(
			os.Getenv("ALICLOUD_ACCESS_KEY"),
			os.Getenv("ALICLOUD_SECRET_KEY"),
		)
	},
	"cloudflare": func() (TXTRecordManager, error) {
		return NewCloudflareTXTManager(os.Getenv("CLOUDFLARE_DNS_API_TOKEN"))
	},
}

// SupportedTXTProviders returns the sorted list of DNS providers the raw
// TXT record API can drive.
func SupportedTXTProviders() []string {
	names := make([]string, 0, len(txtManagerRegistry))
	for k := range txtManagerRegistry {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// NewTXTManager constructs the raw TXT record manager for the given
// provider name.
func NewTXTManager(provider string) (TXTRecordManager, error) {
	factory, ok := txtManagerRegistry[provider]
	if !ok {
		return nil, fmt.Errorf("DNS TXT API does not support provider %q (supported: %v)", provider, SupportedTXTProviders())
	}
	return factory()
}

// AliDNSTXTManager manages DNS TXT records via the AliDNS API.
type AliDNSTXTManager struct {
	client *alidns.Client
}

// NewAliDNSTXTManager creates a new AliDNSTXTManager with AliDNS credentials.
func NewAliDNSTXTManager(accessKey, secretKey string) (*AliDNSTXTManager, error) {
	if accessKey == "" || secretKey == "" {
		return nil, fmt.Errorf("ALICLOUD_ACCESS_KEY and ALICLOUD_SECRET_KEY must be set")
	}

	endpoint := "alidns.aliyuncs.com"

	config := &openapi.Config{
		AccessKeyId:     &accessKey,
		AccessKeySecret: &secretKey,
		Endpoint:        &endpoint,
	}

	client, err := alidns.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create AliDNS client: %w", err)
	}

	return &AliDNSTXTManager{client: client}, nil
}

// AddTXTRecord adds a TXT record for the given FQDN with the specified value.
func (m *AliDNSTXTManager) AddTXTRecord(fqdn, value string) error {
	domain, rr, err := m.resolveZone(fqdn)
	if err != nil {
		return fmt.Errorf("failed to resolve zone: %w", err)
	}

	req := &alidns.AddDomainRecordRequest{}
	req.SetDomainName(domain)
	req.SetRR(rr)
	req.SetType("TXT")
	req.SetValue(value)

	_, err = alidns.AddDomainRecord(m.client, req)
	if err != nil {
		return fmt.Errorf("failed to add TXT record: %w", err)
	}

	return nil
}

// RemoveTXTRecord removes a TXT record matching the given FQDN and value.
func (m *AliDNSTXTManager) RemoveTXTRecord(fqdn, value string) error {
	domain, rr, err := m.resolveZone(fqdn)
	if err != nil {
		return fmt.Errorf("failed to resolve zone: %w", err)
	}

	req := &alidns.DescribeDomainRecordsRequest{}
	req.SetDomainName(domain)
	req.SetRRKeyWord(rr)
	req.SetTypeKeyWord("TXT")

	resp, err := alidns.DescribeDomainRecords(m.client, req)
	if err != nil {
		return fmt.Errorf("failed to query TXT records: %w", err)
	}

	if resp.Body == nil || resp.Body.DomainRecords == nil {
		return nil
	}

	for _, record := range resp.Body.DomainRecords.Record {
		if record.RR != nil && *record.RR == rr &&
			record.Value != nil && *record.Value == value {
			delReq := &alidns.DeleteDomainRecordRequest{}
			delReq.SetRecordId(*record.RecordId)

			_, err = alidns.DeleteDomainRecord(m.client, delReq)
			if err != nil {
				return fmt.Errorf("failed to delete TXT record: %w", err)
			}
			return nil
		}
	}

	return nil
}

// resolveZone finds the AliDNS zone for an FQDN by trying progressively
// shorter domain names until one is found in AliDNS.
func (m *AliDNSTXTManager) resolveZone(fqdn string) (domain, rr string, err error) {
	fqdn = strings.TrimSuffix(fqdn, ".")

	parts := strings.Split(fqdn, ".")
	if len(parts) < 2 {
		return "", "", fmt.Errorf("invalid FQDN: %s", fqdn)
	}

	// Try progressively shorter domain names, starting from longest
	for i := 1; i < len(parts); i++ {
		candidateDomain := strings.Join(parts[i:], ".")
		candidateRR := strings.Join(parts[:i], ".")

		req := &alidns.DescribeDomainRecordsRequest{}
		req.SetDomainName(candidateDomain)
		req.SetPageSize(1)

		_, err := alidns.DescribeDomainRecords(m.client, req)
		if err == nil {
			return candidateDomain, candidateRR, nil
		}
	}

	return "", "", fmt.Errorf("could not find AliDNS zone for FQDN: %s", fqdn)
}
