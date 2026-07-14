package acme

import (
	"context"
	"net"
	"testing"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/miekg/dns"
)

// startFakeDNSServer runs a minimal authoritative DNS server on localhost
// that answers TXT queries for fqdn with value. It returns the server's
// address (host:port) and a shutdown func.
func startFakeDNSServer(t *testing.T, fqdn, value string) string {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	mux := dns.NewServeMux()
	mux.HandleFunc(fqdn, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		rr, err := dns.NewRR(fqdn + ` 60 IN TXT "` + value + `"`)
		if err == nil {
			m.Answer = append(m.Answer, rr)
		}
		_ = w.WriteMsg(m)
	})

	server := &dns.Server{PacketConn: pc, Handler: mux}
	go server.ActivateAndServe()
	t.Cleanup(func() {
		_ = server.Shutdown()
	})

	return pc.LocalAddr().String()
}

func TestRelay_VerifyDNS01Challenge(t *testing.T) {
	domain := "example.com"
	keyAuth := "token123.thumbprint456"
	info := dns01.GetChallengeInfo(domain, keyAuth)

	addr := startFakeDNSServer(t, info.FQDN, info.Value)
	relay := &Relay{recursiveNameservers: []string{addr}}

	if err := relay.VerifyDNS01Challenge(context.Background(), domain, "token123", keyAuth); err != nil {
		t.Fatalf("VerifyDNS01Challenge() error = %v, want nil", err)
	}
}

func TestRelay_VerifyDNS01Challenge_WrongDigest(t *testing.T) {
	domain := "example.com"
	keyAuth := "token123.thumbprint456"
	info := dns01.GetChallengeInfo(domain, keyAuth)

	addr := startFakeDNSServer(t, info.FQDN, "not-the-expected-digest")
	relay := &Relay{recursiveNameservers: []string{addr}}

	if err := relay.VerifyDNS01Challenge(context.Background(), domain, "token123", keyAuth); err == nil {
		t.Fatal("VerifyDNS01Challenge() error = nil, want error for mismatched TXT value")
	}
}

func TestRelay_VerifyDNS01Challenge_NoNameserverReachable(t *testing.T) {
	relay := &Relay{recursiveNameservers: []string{"127.0.0.1:1"}}

	if err := relay.VerifyDNS01Challenge(context.Background(), "example.com", "token123", "token123.thumb"); err == nil {
		t.Fatal("VerifyDNS01Challenge() error = nil, want error when nameserver is unreachable")
	}
}

func TestRelay_VerifyDNS01Challenge_WildcardUsesBaseDomainFQDN(t *testing.T) {
	// Wildcard authorizations carry the base domain (see order.go), so the
	// DNS-01 FQDN queried is identical to the non-wildcard case.
	baseDomain := "example.com"
	keyAuth := "token123.thumbprint456"
	info := dns01.GetChallengeInfo(baseDomain, keyAuth)

	if info.FQDN != "_acme-challenge.example.com." {
		t.Fatalf("FQDN = %q, want _acme-challenge.example.com.", info.FQDN)
	}

	addr := startFakeDNSServer(t, info.FQDN, info.Value)
	relay := &Relay{recursiveNameservers: []string{addr}}

	if err := relay.VerifyDNS01Challenge(context.Background(), baseDomain, "token123", keyAuth); err != nil {
		t.Fatalf("VerifyDNS01Challenge() error = %v, want nil", err)
	}
}
