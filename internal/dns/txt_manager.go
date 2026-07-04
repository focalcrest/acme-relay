// Package dns provides AliDNS integration for DNS-01 challenges.
package dns

import (
	"fmt"
	"strings"

	alidns "github.com/go-acme/alidns-20150109/v4/client"
	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
)

// TXTRecordManager defines the interface for DNS TXT record operations.
type TXTRecordManager interface {
	AddTXTRecord(fqdn, value string) error
	RemoveTXTRecord(fqdn, value string) error
}

// TXTManager manages DNS TXT records via the AliDNS API.
type TXTManager struct {
	client *alidns.Client
}

// NewTXTManager creates a new TXTManager with AliDNS credentials.
func NewTXTManager(accessKey, secretKey, regionID string) (*TXTManager, error) {
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

	return &TXTManager{client: client}, nil
}

// AddTXTRecord adds a TXT record for the given FQDN with the specified value.
func (m *TXTManager) AddTXTRecord(fqdn, value string) error {
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
func (m *TXTManager) RemoveTXTRecord(fqdn, value string) error {
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
func (m *TXTManager) resolveZone(fqdn string) (domain, rr string, err error) {
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
