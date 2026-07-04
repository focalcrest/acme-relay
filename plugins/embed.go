// Package plugins embeds client-side helper scripts so the relay can
// distribute them itself — the served plugin version always matches the
// running server.
package plugins

import _ "embed"

// DNSAcmerelay is the acme.sh dnsapi plugin that delegates DNS-01 TXT
// records to this relay's /api/v1/dns/txt endpoints.
//
//go:embed dns_acmerelay.sh
var DNSAcmerelay []byte
