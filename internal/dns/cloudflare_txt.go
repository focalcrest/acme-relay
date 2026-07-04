package dns

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const cloudflareAPIBase = "https://api.cloudflare.com/client/v4"

// CloudflareTXTManager manages raw DNS TXT records via the Cloudflare v4 API.
type CloudflareTXTManager struct {
	token   string
	baseURL string
	client  *http.Client
}

// NewCloudflareTXTManager creates a new CloudflareTXTManager. The token
// needs the Zone:Read and DNS:Edit permissions on the target zones — the
// same scope lego's cloudflare provider requires.
func NewCloudflareTXTManager(token string) (*CloudflareTXTManager, error) {
	if token == "" {
		return nil, fmt.Errorf("CLOUDFLARE_DNS_API_TOKEN must be set")
	}
	return &CloudflareTXTManager{
		token:   token,
		baseURL: cloudflareAPIBase,
		client:  &http.Client{Timeout: 30 * time.Second},
	}, nil
}

type cfError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e cfError) String() string {
	return fmt.Sprintf("%d: %s", e.Code, e.Message)
}

type cfEnvelope struct {
	Success bool            `json:"success"`
	Errors  []cfError       `json:"errors"`
	Result  json.RawMessage `json:"result"`
}

type cfZone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type cfRecord struct {
	ID      string `json:"id,omitempty"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl,omitempty"`
}

// AddTXTRecord adds a TXT record for the given FQDN with the specified value.
func (m *CloudflareTXTManager) AddTXTRecord(fqdn, value string) error {
	zoneID, err := m.findZone(fqdn)
	if err != nil {
		return fmt.Errorf("failed to resolve zone: %w", err)
	}

	rec := cfRecord{
		Type:    "TXT",
		Name:    strings.TrimSuffix(fqdn, "."),
		Content: value,
		TTL:     120,
	}
	if err := m.do(http.MethodPost, "/zones/"+zoneID+"/dns_records", nil, rec, nil); err != nil {
		return fmt.Errorf("failed to add TXT record: %w", err)
	}
	return nil
}

// RemoveTXTRecord removes TXT records matching the given FQDN and value.
func (m *CloudflareTXTManager) RemoveTXTRecord(fqdn, value string) error {
	zoneID, err := m.findZone(fqdn)
	if err != nil {
		return fmt.Errorf("failed to resolve zone: %w", err)
	}

	query := url.Values{
		"type":    {"TXT"},
		"name":    {strings.TrimSuffix(fqdn, ".")},
		"content": {value},
	}
	var records []cfRecord
	if err := m.do(http.MethodGet, "/zones/"+zoneID+"/dns_records", query, nil, &records); err != nil {
		return fmt.Errorf("failed to query TXT records: %w", err)
	}

	for _, rec := range records {
		if err := m.do(http.MethodDelete, "/zones/"+zoneID+"/dns_records/"+rec.ID, nil, nil, nil); err != nil {
			return fmt.Errorf("failed to delete TXT record: %w", err)
		}
	}
	return nil
}

// findZone locates the Cloudflare zone containing the FQDN by trying
// progressively shorter domain names, mirroring the AliDNS resolveZone logic.
func (m *CloudflareTXTManager) findZone(fqdn string) (string, error) {
	fqdn = strings.TrimSuffix(fqdn, ".")

	parts := strings.Split(fqdn, ".")
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid FQDN: %s", fqdn)
	}

	for i := 1; i < len(parts); i++ {
		candidate := strings.Join(parts[i:], ".")

		var zones []cfZone
		if err := m.do(http.MethodGet, "/zones", url.Values{"name": {candidate}}, nil, &zones); err != nil {
			return "", err
		}
		if len(zones) > 0 {
			return zones[0].ID, nil
		}
	}

	return "", fmt.Errorf("could not find Cloudflare zone for FQDN: %s", fqdn)
}

// do performs an API call and unmarshals the result envelope into result
// (which may be nil when the caller only cares about success).
func (m *CloudflareTXTManager) do(method, path string, query url.Values, body, result interface{}) error {
	u := m.baseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}

	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("cloudflare API %s %s: encode request: %w", method, path, err)
		}
		reqBody = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, u, reqBody)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+m.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var env cfEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return fmt.Errorf("cloudflare API %s %s: HTTP %d: decode response: %w", method, path, resp.StatusCode, err)
	}
	if !env.Success {
		return fmt.Errorf("cloudflare API %s %s: HTTP %d: %v", method, path, resp.StatusCode, env.Errors)
	}
	if result != nil {
		if err := json.Unmarshal(env.Result, result); err != nil {
			return fmt.Errorf("cloudflare API %s %s: decode result: %w", method, path, err)
		}
	}
	return nil
}
