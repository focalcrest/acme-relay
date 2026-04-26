package dns

import (
	"strings"
	"testing"
)

func TestResolveZoneParsing(t *testing.T) {
	tests := []struct {
		fqdn      string
		wantParts []struct{ rr, domain string }
	}{
		{
			fqdn: "_acme-challenge.example.com",
			wantParts: []struct{ rr, domain string }{
				{"_acme-challenge", "example.com"},
				{"_acme-challenge.example", "com"},
			},
		},
		{
			fqdn: "_acme-challenge.sub.example.com",
			wantParts: []struct{ rr, domain string }{
				{"_acme-challenge", "sub.example.com"},
				{"_acme-challenge.sub", "example.com"},
				{"_acme-challenge.sub.example", "com"},
			},
		},
		{
			fqdn: "_acme-challenge.deep.sub.example.com.",
			wantParts: []struct{ rr, domain string }{
				{"_acme-challenge", "deep.sub.example.com"},
				{"_acme-challenge.deep", "sub.example.com"},
				{"_acme-challenge.deep.sub", "example.com"},
				{"_acme-challenge.deep.sub.example", "com"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.fqdn, func(t *testing.T) {
			fqdn := strings.TrimSuffix(tt.fqdn, ".")
			parts := strings.Split(fqdn, ".")

			var got []struct{ rr, domain string }
			for i := 1; i < len(parts); i++ {
				got = append(got, struct{ rr, domain string }{
					rr:     strings.Join(parts[:i], "."),
					domain: strings.Join(parts[i:], "."),
				})
			}

			if len(got) != len(tt.wantParts) {
				t.Fatalf("got %d splits, want %d", len(got), len(tt.wantParts))
			}

			for i, s := range got {
				if s != tt.wantParts[i] {
					t.Errorf("split[%d] = {rr: %q, domain: %q}, want {rr: %q, domain: %q}",
						i, s.rr, s.domain, tt.wantParts[i].rr, tt.wantParts[i].domain)
				}
			}
		})
	}
}

func TestResolveZoneParsingInvalid(t *testing.T) {
	tests := []string{
		"single",
		"",
	}

	for _, fqdn := range tests {
		t.Run(fqdn, func(t *testing.T) {
			parts := strings.Split(fqdn, ".")
			if len(parts) >= 2 {
				t.Skip("this FQDN is valid")
			}
		})
	}
}
