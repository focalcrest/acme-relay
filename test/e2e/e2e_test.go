package e2e

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-jose/go-jose/v4"

	"github.com/focalcrest/acme-relay/internal/acme"
	"github.com/focalcrest/acme-relay/internal/handler"
	"github.com/focalcrest/acme-relay/internal/storage"
)

// setupE2EServer creates a full ACME test server (nil relay) with the same
// route layout as production. Returns the server and the underlying store so
// tests can manipulate state when needed.
func setupE2EServer(t *testing.T) (*httptest.Server, *storage.FilesystemStorage) {
	t.Helper()

	dir := t.TempDir()
	store, err := storage.NewFilesystemStorage(dir)
	if err != nil {
		t.Fatalf("storage: %v", err)
	}

	nonceSvc := acme.NewNonceService()
	idGen := acme.NewIDGenerator(0)

	// Allocate listener port upfront so the handler baseURL matches the server.
	srv := httptest.NewUnstartedServer(http.NewServeMux())
	baseURL := "http://" + srv.Listener.Addr().String()

	h := handler.NewACMEHandler(store, nil, nonceSvc, idGen, baseURL)

	r := chi.NewRouter()
	r.Route("/acme", func(r chi.Router) {
		r.Get("/directory", h.Directory)
		r.Head("/new-nonce", h.NewNonce)
		r.Get("/new-nonce", h.NewNonce)

		r.With(acme.JWSWithJWKMiddleware(nonceSvc)).Post("/new-account", h.NewAccount)

		r.Route("/", func(r chi.Router) {
			r.Use(acme.JWSMiddleware(nonceSvc, store.GetAccountByKIDURL))

			r.Post("/new-order", h.NewOrder)
			r.Post("/order/{id}", h.GetOrder)
			r.Post("/order/{id}/finalize", h.FinalizeOrder)
			r.Post("/authz/{id}", h.GetAuthorization)
			r.Post("/challenge/{authzID}/{chalID}", h.HandleChallenge)
			r.Post("/certificate/{orderID}", h.GetCertificate)
		})
	})

	srv.Config.Handler = r
	srv.Start()
	t.Cleanup(srv.Close)

	return srv, store
}

// ── JWS helpers ──

func signJWSWithJWK(key *ecdsa.PrivateKey, url, nonce string, payload interface{}) (string, error) {
	b, _ := json.Marshal(payload)
	signer, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: key},
		&jose.SignerOptions{
			EmbedJWK: true,
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"url":   url,
				"nonce": nonce,
			},
		},
	)
	obj, _ := signer.Sign(b)
	return obj.CompactSerialize()
}

func signJWSWithKID(key *ecdsa.PrivateKey, kid, url, nonce string, payload interface{}) (string, error) {
	b, _ := json.Marshal(payload)
	signer, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: key},
		&jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"url":   url,
				"nonce": nonce,
				"kid":   kid,
			},
		},
	)
	obj, _ := signer.Sign(b)
	return obj.CompactSerialize()
}

// ── Small helpers ──

func fetchNonce(client *http.Client, url string) string {
	resp, err := client.Get(url)
	if err != nil {
		return ""
	}
	resp.Body.Close()
	return resp.Header.Get("Replay-Nonce")
}

func lastSegment(u string) string {
	return u[strings.LastIndex(u, "/")+1:]
}

func orderIDFromFinalize(u string) string {
	parts := strings.Split(u, "/")
	for i, p := range parts {
		if p == "order" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

func postACME(client *http.Client, url, jwsBody string) *http.Response {
	resp, err := client.Post(url, "application/jose+json", strings.NewReader(jwsBody))
	if err != nil {
		return nil
	}
	return resp
}

func readErrorBody(resp *http.Response) string {
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

// ── Tests ──

// TestE2E_FullACMEFlow exercises the complete ACME protocol sequence through
// a real HTTP server with full JWS middleware: directory → nonce → account →
// order → authorization → challenge → (simulate verification) → finalize.
func TestE2E_FullACMEFlow(t *testing.T) {
	srv, store := setupE2EServer(t)
	client := srv.Client()
	base := srv.URL

	// ── 1. Directory ──
	resp, err := client.Get(base + "/acme/directory")
	if err != nil {
		t.Fatalf("directory: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("directory status = %d, want 200", resp.StatusCode)
	}

	var dir map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&dir); err != nil {
		t.Fatalf("decode directory: %v", err)
	}
	for _, key := range []string{"newNonce", "newAccount", "newOrder"} {
		if _, ok := dir[key]; !ok {
			t.Errorf("directory missing %q", key)
		}
	}

	// ── 2. Nonce ──
	nonce := fetchNonce(client, base+"/acme/new-nonce")
	if nonce == "" {
		t.Fatal("empty nonce")
	}

	// ── 3. Create account ──
	acctKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	acctURL := base + "/acme/new-account"

	jws, _ := signJWSWithJWK(acctKey, acctURL, nonce, map[string]interface{}{
		"termsOfServiceAgreed": true,
		"email":                "e2e@example.com",
	})
	resp = postACME(client, acctURL, jws)
	if resp == nil {
		t.Fatal("account request failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("account status = %d, want 201; body: %s", resp.StatusCode, readErrorBody(resp))
	}

	nonce = resp.Header.Get("Replay-Nonce")
	kid := resp.Header.Get("Location")

	var acct struct {
		Status string `json:"status"`
		Orders string `json:"orders"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&acct); err != nil {
		t.Fatalf("decode account: %v", err)
	}
	if acct.Status != "valid" {
		t.Errorf("account status = %q, want valid", acct.Status)
	}

	// ── 4. Create order ──
	orderURL := base + "/acme/new-order"
	jws, _ = signJWSWithKID(acctKey, kid, orderURL, nonce, acme.OrderCreateRequest{
		Identifiers: []acme.Identifier{
			{Type: "dns", Value: "test.example.com"},
		},
	})
	resp = postACME(client, orderURL, jws)
	if resp == nil {
		t.Fatal("order request failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("order status = %d, want 201; body: %s", resp.StatusCode, readErrorBody(resp))
	}

	nonce = resp.Header.Get("Replay-Nonce")

	var order struct {
		Status         string            `json:"status"`
		Identifiers    []acme.Identifier `json:"identifiers"`
		Authorizations []string          `json:"authorizations"`
		Finalize       string            `json:"finalize"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&order); err != nil {
		t.Fatalf("decode order: %v", err)
	}
	if order.Status != "pending" {
		t.Errorf("order status = %q, want pending", order.Status)
	}
	if len(order.Authorizations) != 1 {
		t.Fatalf("authorizations = %d, want 1", len(order.Authorizations))
	}

	authzIDStr := lastSegment(order.Authorizations[0])
	authzID, _ := strconv.ParseInt(authzIDStr, 10, 64)

	// ── 5. Get authorization ──
	authzEndpoint := base + "/acme/authz/" + authzIDStr
	jws, _ = signJWSWithKID(acctKey, kid, authzEndpoint, nonce, map[string]interface{}{})
	resp = postACME(client, authzEndpoint, jws)
	if resp == nil {
		t.Fatal("authz request failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authz status = %d, want 200; body: %s", resp.StatusCode, readErrorBody(resp))
	}

	nonce = resp.Header.Get("Replay-Nonce")

	var authz struct {
		Status     string `json:"status"`
		Challenges []struct {
			Type   string `json:"type"`
			URL    string `json:"url"`
			Token  string `json:"token"`
			Status string `json:"status"`
		} `json:"challenges"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&authz); err != nil {
		t.Fatalf("decode authz: %v", err)
	}
	if authz.Status != "pending" {
		t.Errorf("authz status = %q, want pending", authz.Status)
	}
	if len(authz.Challenges) == 0 {
		t.Fatal("no challenges")
	}

	// ── 6. Respond to challenge ──
	chalURL := authz.Challenges[0].URL
	parts := strings.Split(chalURL, "/")
	chalAuthzID := parts[len(parts)-2]
	chalIdx := parts[len(parts)-1]

	chalEndpoint := base + "/acme/challenge/" + chalAuthzID + "/" + chalIdx
	jws, _ = signJWSWithKID(acctKey, kid, chalEndpoint, nonce, map[string]interface{}{})
	resp = postACME(client, chalEndpoint, jws)
	if resp == nil {
		t.Fatal("challenge request failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("challenge status = %d, want 200; body: %s", resp.StatusCode, readErrorBody(resp))
	}

	nonce = resp.Header.Get("Replay-Nonce")

	var chal struct {
		Status           string `json:"status"`
		Token            string `json:"token"`
		KeyAuthorization string `json:"keyAuthorization"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&chal); err != nil {
		t.Fatalf("decode challenge: %v", err)
	}
	if chal.Status != "processing" {
		t.Errorf("challenge status = %q, want processing", chal.Status)
	}
	if chal.Token == "" || chal.KeyAuthorization == "" {
		t.Error("challenge missing token or keyAuthorization")
	}

	// ── 7. Simulate verification (relay is nil, goroutine did nothing) ──
	storedAuthz, err := store.GetAuthorization(authzID)
	if err != nil {
		t.Fatalf("get authz from store: %v", err)
	}
	storedAuthz.Status = acme.AuthzStatusValid
	storedAuthz.Challenges[0].Status = acme.ChallengeStatusValid
	storedAuthz.Challenges[0].Validated = time.Now()
	if err := store.SaveAuthorization(storedAuthz); err != nil {
		t.Fatalf("save authz: %v", err)
	}

	orderIDStr := orderIDFromFinalize(order.Finalize)
	orderID, _ := strconv.ParseInt(orderIDStr, 10, 64)
	storedOrder, err := store.GetOrder(orderID)
	if err != nil {
		t.Fatalf("get order from store: %v", err)
	}
	storedOrder.Status = acme.OrderStatusReady
	if err := store.SaveOrder(storedOrder); err != nil {
		t.Fatalf("save order: %v", err)
	}

	// ── 8. Verify order transitioned to ready ──
	getOrderEndpoint := base + "/acme/order/" + orderIDStr
	jws, _ = signJWSWithKID(acctKey, kid, getOrderEndpoint, nonce, map[string]interface{}{})
	resp = postACME(client, getOrderEndpoint, jws)
	if resp == nil {
		t.Fatal("get-order request failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get-order status = %d, want 200; body: %s", resp.StatusCode, readErrorBody(resp))
	}

	nonce = resp.Header.Get("Replay-Nonce")

	var readyOrder struct {
		Status   string `json:"status"`
		Finalize string `json:"finalize"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&readyOrder); err != nil {
		t.Fatalf("decode order: %v", err)
	}
	if readyOrder.Status != "ready" {
		t.Errorf("order status = %q, want ready", readyOrder.Status)
	}

	// ── 9. Finalize with wrong-domain CSR (safe: rejected before relay call) ──
	csrKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "wrong.example.com"},
		DNSNames: []string{"wrong.example.com"},
	}, csrKey)
	csrB64 := base64.RawURLEncoding.EncodeToString(csrDER)

	finalizeEndpoint := base + "/acme/order/" + orderIDStr + "/finalize"
	jws, _ = signJWSWithKID(acctKey, kid, finalizeEndpoint, nonce, acme.FinalizeRequest{
		CSR: csrB64,
	})
	resp = postACME(client, finalizeEndpoint, jws)
	if resp == nil {
		t.Fatal("finalize request failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("finalize(wrong CSR) status = %d, want 400; body: %s",
			resp.StatusCode, readErrorBody(resp))
	}

	// Order should remain ready after rejected finalize
	storedOrder, _ = store.GetOrder(orderID)
	if storedOrder.Status != acme.OrderStatusReady {
		t.Errorf("order status after bad finalize = %q, want ready", storedOrder.Status)
	}

	// ── 10. Duplicate account key returns existing ──
	nonce = fetchNonce(client, base+"/acme/new-nonce")
	jws, _ = signJWSWithJWK(acctKey, acctURL, nonce, map[string]interface{}{
		"termsOfServiceAgreed": true,
	})
	resp = postACME(client, acctURL, jws)
	if resp == nil {
		t.Fatal("duplicate account request failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("duplicate account status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); got != kid {
		t.Errorf("duplicate account Location = %q, want %q", got, kid)
	}
}

// TestE2E_NonceReplayProtection verifies that reusing a nonce is rejected.
func TestE2E_NonceReplayProtection(t *testing.T) {
	srv, _ := setupE2EServer(t)
	client := srv.Client()
	base := srv.URL

	nonce := fetchNonce(client, base+"/acme/new-nonce")
	if nonce == "" {
		t.Fatal("empty nonce")
	}

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	acctURL := base + "/acme/new-account"

	// Consume the nonce.
	jws, _ := signJWSWithJWK(key, acctURL, nonce, map[string]interface{}{
		"termsOfServiceAgreed": true,
		"email":                "replay@example.com",
	})
	resp := postACME(client, acctURL, jws)
	if resp == nil {
		t.Fatal("first request failed")
	}
	resp.Body.Close()

	// Reuse the same nonce — must fail.
	jws2, _ := signJWSWithJWK(key, acctURL, nonce, map[string]interface{}{
		"termsOfServiceAgreed": true,
	})
	resp = postACME(client, acctURL, jws2)
	if resp == nil {
		t.Fatal("replay request failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
		t.Error("nonce replay should be rejected")
	}

	var prob struct {
		Type string `json:"type"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&prob); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if prob.Type != "urn:ietf:params:acme:error:badNonce" {
		t.Errorf("error type = %q, want badNonce", prob.Type)
	}
}

// TestE2E_FinalizePendingOrder verifies that finalizing a non-ready order is
// rejected with 403 Forbidden.
func TestE2E_FinalizePendingOrder(t *testing.T) {
	srv, _ := setupE2EServer(t)
	client := srv.Client()
	base := srv.URL

	// Quick account + order setup.
	nonce := fetchNonce(client, base+"/acme/new-nonce")
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	acctURL := base + "/acme/new-account"

	jws, _ := signJWSWithJWK(key, acctURL, nonce, map[string]interface{}{
		"termsOfServiceAgreed": true,
		"email":                "pending@example.com",
	})
	resp := postACME(client, acctURL, jws)
	if resp == nil {
		t.Fatal("account request failed")
	}
	resp.Body.Close()
	nonce = resp.Header.Get("Replay-Nonce")
	kid := resp.Header.Get("Location")

	// Create order (leaves it pending).
	newOrderURL := base + "/acme/new-order"
	jws, _ = signJWSWithKID(key, kid, newOrderURL, nonce,
		acme.OrderCreateRequest{
			Identifiers: []acme.Identifier{
				{Type: "dns", Value: "pending.example.com"},
			},
		},
	)
	resp = postACME(client, newOrderURL, jws)
	if resp == nil {
		t.Fatal("order request failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("order status = %d, want 201; body: %s", resp.StatusCode, readErrorBody(resp))
	}

	var order struct {
		Finalize string `json:"finalize"`
	}
	json.NewDecoder(resp.Body).Decode(&order)

	nonce = resp.Header.Get("Replay-Nonce")

	// Attempt finalize on pending order.
	orderIDStr := orderIDFromFinalize(order.Finalize)
	finalizeURL := base + "/acme/order/" + orderIDStr + "/finalize"

	jws, _ = signJWSWithKID(key, kid, finalizeURL, nonce,
		acme.FinalizeRequest{CSR: "aW52YWxpZA"},
	)
	resp = postACME(client, finalizeURL, jws)
	if resp == nil {
		t.Fatal("finalize request failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("finalize(pending) status = %d, want 403; body: %s",
			resp.StatusCode, readErrorBody(resp))
	}
}
