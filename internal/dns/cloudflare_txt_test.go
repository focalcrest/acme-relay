package dns

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// cfFake fakes the Cloudflare v4 API surface the manager uses: zone
// lookup, record create, record list, and record delete. It hosts a
// single zone "example.com" with ID "zone123".
type cfFake struct {
	t       *testing.T
	records map[string]cfRecord
	nextID  int
}

func writeCFResponse(w http.ResponseWriter, status int, success bool, result interface{}, errs []cfError) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	data, _ := json.Marshal(result)
	json.NewEncoder(w).Encode(cfEnvelope{Success: success, Errors: errs, Result: data})
}

func (f *cfFake) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			writeCFResponse(w, http.StatusForbidden, false, nil, []cfError{{Code: 9109, Message: "Invalid access token"}})
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones":
			if r.URL.Query().Get("name") == "example.com" {
				writeCFResponse(w, http.StatusOK, true, []cfZone{{ID: "zone123", Name: "example.com"}}, nil)
			} else {
				writeCFResponse(w, http.StatusOK, true, []cfZone{}, nil)
			}
		case r.Method == http.MethodPost && r.URL.Path == "/zones/zone123/dns_records":
			var rec cfRecord
			if err := json.NewDecoder(r.Body).Decode(&rec); err != nil {
				f.t.Errorf("bad record body: %v", err)
			}
			f.nextID++
			rec.ID = fmt.Sprintf("rec%d", f.nextID)
			f.records[rec.ID] = rec
			writeCFResponse(w, http.StatusOK, true, rec, nil)
		case r.Method == http.MethodGet && r.URL.Path == "/zones/zone123/dns_records":
			q := r.URL.Query()
			out := []cfRecord{}
			for _, rec := range f.records {
				if rec.Type == q.Get("type") && rec.Name == q.Get("name") && rec.Content == q.Get("content") {
					out = append(out, rec)
				}
			}
			writeCFResponse(w, http.StatusOK, true, out, nil)
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/zones/zone123/dns_records/"):
			id := strings.TrimPrefix(r.URL.Path, "/zones/zone123/dns_records/")
			if _, ok := f.records[id]; !ok {
				writeCFResponse(w, http.StatusNotFound, false, nil, []cfError{{Code: 81044, Message: "Record does not exist"}})
				return
			}
			delete(f.records, id)
			writeCFResponse(w, http.StatusOK, true, map[string]string{"id": id}, nil)
		default:
			f.t.Errorf("unexpected request: %s %s", r.Method, r.URL)
			writeCFResponse(w, http.StatusNotFound, false, nil, []cfError{{Code: 7000, Message: "No route"}})
		}
	}
}

func newCFTestManager(t *testing.T, token string) (*CloudflareTXTManager, *cfFake) {
	t.Helper()
	fake := &cfFake{t: t, records: map[string]cfRecord{}}
	srv := httptest.NewServer(fake.handler())
	t.Cleanup(srv.Close)

	m, err := NewCloudflareTXTManager(token)
	if err != nil {
		t.Fatalf("NewCloudflareTXTManager: %v", err)
	}
	m.baseURL = srv.URL
	return m, fake
}

func TestCloudflareAddTXTRecord(t *testing.T) {
	m, fake := newCFTestManager(t, "test-token")

	// Zone probing must skip "portal.example.com" and land on "example.com".
	if err := m.AddTXTRecord("_acme-challenge.portal.example.com.", "test-value"); err != nil {
		t.Fatalf("AddTXTRecord: %v", err)
	}

	if len(fake.records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(fake.records))
	}
	for _, rec := range fake.records {
		if rec.Type != "TXT" || rec.Name != "_acme-challenge.portal.example.com" || rec.Content != "test-value" {
			t.Errorf("unexpected record: %+v", rec)
		}
	}
}

func TestCloudflareRemoveTXTRecord(t *testing.T) {
	m, fake := newCFTestManager(t, "test-token")
	fake.records["rec1"] = cfRecord{ID: "rec1", Type: "TXT", Name: "_acme-challenge.example.com", Content: "test-value"}
	fake.records["rec2"] = cfRecord{ID: "rec2", Type: "TXT", Name: "_acme-challenge.example.com", Content: "other-value"}

	if err := m.RemoveTXTRecord("_acme-challenge.example.com", "test-value"); err != nil {
		t.Fatalf("RemoveTXTRecord: %v", err)
	}

	if _, ok := fake.records["rec1"]; ok {
		t.Error("matching record should have been deleted")
	}
	if _, ok := fake.records["rec2"]; !ok {
		t.Error("record with a different value must survive")
	}
}

func TestCloudflareZoneNotFound(t *testing.T) {
	m, fake := newCFTestManager(t, "test-token")

	if err := m.AddTXTRecord("_acme-challenge.other.org", "test-value"); err == nil {
		t.Fatal("expected error for FQDN outside any hosted zone")
	}
	if len(fake.records) != 0 {
		t.Errorf("no record should have been created, got %v", fake.records)
	}
}

func TestCloudflareBadToken(t *testing.T) {
	m, _ := newCFTestManager(t, "wrong-token")

	if err := m.AddTXTRecord("_acme-challenge.example.com", "test-value"); err == nil {
		t.Fatal("expected error for rejected token")
	}
}

func TestNewTXTManagerUnsupportedProvider(t *testing.T) {
	if _, err := NewTXTManager("gcloud"); err == nil {
		t.Fatal("expected error for provider without TXT API support")
	}
}

func TestNewTXTManagerMissingCredentials(t *testing.T) {
	t.Setenv("CLOUDFLARE_DNS_API_TOKEN", "")
	if _, err := NewTXTManager("cloudflare"); err == nil {
		t.Fatal("expected error when CLOUDFLARE_DNS_API_TOKEN is empty")
	}

	t.Setenv("ALICLOUD_ACCESS_KEY", "")
	t.Setenv("ALICLOUD_SECRET_KEY", "")
	if _, err := NewTXTManager("alidns"); err == nil {
		t.Fatal("expected error when AliDNS credentials are empty")
	}
}
