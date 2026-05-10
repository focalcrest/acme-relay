package dns

import (
	"fmt"
	"sort"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/providers/dns/alidns"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/providers/dns/digitalocean"
	"github.com/go-acme/lego/v4/providers/dns/gcloud"
	"github.com/go-acme/lego/v4/providers/dns/route53"
	"github.com/go-acme/lego/v4/providers/dns/tencentcloud"
)

// providerFactory builds a lego DNS-01 provider that reads its own
// credentials from environment variables. The runtime is expected to
// export config.DNS.Credentials into the process environment before
// calling this.
type providerFactory func() (challenge.Provider, error)

var providerRegistry = map[string]providerFactory{
	"alidns":       func() (challenge.Provider, error) { return alidns.NewDNSProvider() },
	"cloudflare":   func() (challenge.Provider, error) { return cloudflare.NewDNSProvider() },
	"route53":      func() (challenge.Provider, error) { return route53.NewDNSProvider() },
	"gcloud":       func() (challenge.Provider, error) { return gcloud.NewDNSProvider() },
	"digitalocean": func() (challenge.Provider, error) { return digitalocean.NewDNSProvider() },
	"dnspod":       func() (challenge.Provider, error) { return tencentcloud.NewDNSProvider() },
	"tencentcloud": func() (challenge.Provider, error) { return tencentcloud.NewDNSProvider() },
}

// SupportedProviders returns the sorted list of DNS provider names this
// build accepts. Useful for error messages and documentation.
func SupportedProviders() []string {
	names := make([]string, 0, len(providerRegistry))
	for k := range providerRegistry {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// NewProvider constructs a DNS-01 challenge provider for the given name.
// Each provider reads its credentials from environment variables — see
// the lego documentation for the variables each backend expects.
func NewProvider(name string) (challenge.Provider, error) {
	factory, ok := providerRegistry[name]
	if !ok {
		return nil, fmt.Errorf("unsupported DNS provider %q (supported: %v)", name, SupportedProviders())
	}
	return factory()
}
