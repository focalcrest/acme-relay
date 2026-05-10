# acme-relay

**Real, browser-trusted Let's Encrypt certificates for internal servers — without giving each one DNS API credentials, public ACME reachability, or a private root CA to distribute.**

`acme-relay` is an [RFC 8555](https://datatracker.ietf.org/doc/html/rfc8555) ACME server that internal hosts talk to using ordinary clients (`acme.sh`, `certbot`, `lego`, `cert-manager`). Behind the scenes it relays each order to a public CA (Let's Encrypt by default) over DNS-01, returning a real, publicly-trusted certificate.

```
internal host                     acme-relay                    Let's Encrypt
┌──────────────┐   HTTP-01      ┌─────────────┐    DNS-01      ┌──────────────┐
│ acme.sh      │  ───────────►  │ RFC 8555    │  ───────────►  │ acme-v02     │
│ certbot      │                │ ACME server │                │ .api.lets... │
│ lego         │  ◄───────────  │             │  ◄───────────  │              │
└──────────────┘   real LE      └─────────────┘                └──────────────┘
                   certificate         │
                                       │ DNS-01 TXT
                                       ▼
                                  ┌─────────────┐
                                  │ DNS provider│
                                  │ (Cloudflare,│
                                  │ Route 53,…) │
                                  └─────────────┘
```

## Why this exists

Internal infrastructure usually has three uncomfortable choices:

| Approach                          | Problem                                                                           |
| --------------------------------- | --------------------------------------------------------------------------------- |
| Private CA (`step-ca`, Vault PKI) | Browsers don't trust it. Root must be pushed to every client, browser, container. |
| Run ACME on every host            | Each host needs DNS API credentials *and* outbound access to Let's Encrypt.       |
| Issue centrally, push over SSH    | SSH-key sprawl, restart logic per service, certificates rot when scripts break.   |

`acme-relay` collapses these into one HTTPS endpoint. Internal clients see a normal ACME server. Credentials and public reachability live in exactly one place.

### vs. similar projects

Each row is "✅ = the user gets this benefit." `acme-relay` is the only project that ticks every box.

|                                                | `step-ca` | `acme-dns` | `cert-manager` | **`acme-relay`** |
| ---------------------------------------------- | --------- | ---------- | -------------- | ---------------- |
| Issues browser-trusted certificates            | ❌         | ✅          | ✅              | ✅                |
| Clients don't need reachability to a public CA | ✅         | ❌          | ❌              | ✅                |
| Clients don't need any DNS API credentials     | ✅         | ❌          | ❌              | ✅                |
| Standard RFC 8555 server for any ACME client   | ✅         | ❌          | ❌              | ✅                |

`step-ca` matches every operational property but issues from its own CA, so the resulting certificates aren't browser-trusted without distributing a private root. `acme-dns` and `cert-manager` produce real LE certificates but require each client to reach LE itself and (for `cert-manager`) hold DNS credentials. `acme-relay` keeps the trust story of public LE *and* the "credentials live in one place" property of a private CA.

## Install

Pick whichever fits — both produce the same binary.

```bash
# 1. Pre-built binary (no Go toolchain required)
#    Available for linux-amd64 and linux-arm64.
#    See https://github.com/focalcrest/acme-relay/releases for the latest tag.
curl -L https://github.com/focalcrest/acme-relay/releases/latest/download/acme-relay_linux_amd64.tar.gz \
  | tar xz
sudo install -m 0755 acme-relay /usr/local/bin/

# 2. go install (requires Go 1.24+; compiles locally)
go install github.com/focalcrest/acme-relay/cmd/acme-relay@latest
# binary lands at $(go env GOBIN)/acme-relay

# 3. From source
git clone https://github.com/focalcrest/acme-relay.git && cd acme-relay
go build ./cmd/acme-relay
```

## Quickstart

```bash
# Write config next to the binary
cat > acme-relay.yaml <<'EOF'
server:
  host: "127.0.0.1"
  port: 8080
  baseUrl: "https://acme.example.com"     # public URL clients use

acme:
  provider: "letsencrypt"                 # or "staging" while testing
  email: "admin@example.com"

dns:
  provider: "cloudflare"                  # see "Supported DNS providers" below
  credentials:
    CLOUDFLARE_DNS_API_TOKEN: "..."       # scoped Zone:DNS:Edit token

storage:
  type: "filesystem"
  path: "/var/lib/acme-relay/certs"
EOF

# Run
./acme-relay
```

Then on any internal host:

```bash
acme.sh --issue \
  -d host01.example.com \
  --standalone --httpport 80 \
  --server https://acme.example.com/acme/directory
```

## Configuration

| Section                   | Key                    | Description                                                              |
| ------------------------- | ---------------------- | ------------------------------------------------------------------------ |
| `server.host`             | string                 | Bind address. Use `127.0.0.1` if running behind a reverse proxy.         |
| `server.port`             | int                    | Bind port.                                                               |
| `server.baseUrl`          | string                 | Public URL clients see. Used in directory/order/cert URLs.               |
| `acme.provider`           | `letsencrypt` / `staging` / URL | Upstream CA. Use `staging` while testing.                       |
| `acme.email`              | string                 | Account email registered with the upstream CA.                           |
| `dns.provider`            | string                 | Upstream DNS-01 provider. See *Supported DNS providers* below.           |
| `dns.credentials`         | map[string]string      | Provider credentials, keyed by lego env-var name (e.g. `ALICLOUD_ACCESS_KEY`, `CLOUDFLARE_DNS_API_TOKEN`). Exported as env vars at startup. |
| `dns.recursiveNameservers`| []string               | Optional. See *split-horizon DNS* below.                                 |
| `storage.path`            | string                 | Certificate, account, and order persistence directory.                   |

Environment variable overrides use the prefix `ACME_RELAY_`, e.g. `ACME_RELAY_SERVER_PORT`.

## Supported DNS providers

The build links a focused set of [lego](https://github.com/go-acme/lego)'s DNS-01 backends. Each provider reads its credentials from the env-var-shaped keys you put under `dns.credentials`:

| `dns.provider`                | Required `dns.credentials` keys                                                  | Notes                                              |
| ----------------------------- | -------------------------------------------------------------------------------- | -------------------------------------------------- |
| `alidns`                      | `ALICLOUD_ACCESS_KEY`, `ALICLOUD_SECRET_KEY` (`ALICLOUD_REGION_ID` optional)     | Aliyun DNS                                         |
| `cloudflare`                  | `CLOUDFLARE_DNS_API_TOKEN` (scoped) — or `CLOUDFLARE_EMAIL` + `CLOUDFLARE_API_KEY` (legacy) | Cloudflare                                         |
| `route53`                     | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION`                       | AWS Route 53. IAM-role auth also works (no creds)  |
| `gcloud`                      | `GCE_PROJECT` + `GCE_SERVICE_ACCOUNT_FILE` (or `GOOGLE_APPLICATION_CREDENTIALS`) | Google Cloud DNS                                   |
| `digitalocean`                | `DO_AUTH_TOKEN`                                                                  | DigitalOcean                                       |
| `dnspod` (alias `tencentcloud`) | `TENCENTCLOUD_SECRET_ID`, `TENCENTCLOUD_SECRET_KEY` (`TENCENTCLOUD_REGION` optional) | Tencent Cloud DNSPod                               |

Adding more is a one-line change in `internal/dns/registry.go`. Each lego provider has additional optional env vars (TTL, polling, propagation timeout) — see [lego's docs](https://go-acme.github.io/lego/dns/) for the full list.

## RFC 8555 endpoints

```
GET  /acme/directory
HEAD /acme/new-nonce
POST /acme/new-account
POST /acme/new-order
POST /acme/order/{id}
POST /acme/order/{id}/finalize
POST /acme/authz/{id}
POST /acme/challenge/{authzID}/{chalID}
POST /acme/certificate/{orderID}
GET  /health
```

Tested against `acme.sh` end-to-end. The server validates JWS signatures, nonces, account binding, and the protected `url` field per RFC 8555 §6.

## Behind a reverse proxy

The recommended deployment binds the relay to `127.0.0.1` and lets nginx (or similar) terminate TLS:

```nginx
server {
    listen 443 ssl;
    server_name acme.example.com;

    ssl_certificate     /etc/ssl/acme.example.com/fullchain.cer;
    ssl_certificate_key /etc/ssl/acme.example.com/privkey.key;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host              $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 180s;
    }
}
```

`X-Forwarded-Proto` is required: clients sign the JWS protected header with the public `https://...` URL, and the relay needs that hint to validate the URL match per RFC 8555 §6.4.

## Split-horizon DNS

If your internal DNS treats a subdomain as its own zone but the public view has it as a label inside a larger zone — a common pattern when an internal AD/DNS server is authoritative for, say, `internal.example.com`, while the public zone (the one your DNS provider hosts) is `example.com` — the upstream provider's zone discovery can fail because the SOA seen via the system resolver doesn't match the public zone.

Set `dns.recursiveNameservers` to public resolvers so SOA lookups bypass the internal view:

```yaml
dns:
  recursiveNameservers:
    - "1.1.1.1:53"       # Cloudflare
    - "8.8.8.8:53"       # Google
```

Use whichever public resolvers are reachable from the relay host.

## Status & limitations

Tested in production-shaped use:

- ✅ End-to-end issuance with `acme.sh` against Let's Encrypt staging and production.
- ✅ Full RFC 8555 flow: account, order, HTTP-01 challenge, DNS-01 upstream, finalize, certificate retrieval.
- ✅ Behind nginx with TLS termination and `X-Forwarded-Proto`.
- ✅ Split-horizon DNS environments (with `recursiveNameservers` configured).

Not yet implemented (PRs welcome):

- High-availability (etcd/consul-backed storage). Filesystem storage is the only backend.
- Per-account / per-domain rate limiting.
- Prometheus metrics.
- Certificate revocation endpoint.
- TLS termination in the relay itself (currently relies on a reverse proxy for TLS).

## Building and testing

```bash
go test ./...                     # unit + e2e
go build ./cmd/acme-relay         # production binary
go run ./cmd/verify-staging       # smoke test against LE staging
```

## License

Apache License 2.0 — see [LICENSE](./LICENSE).
