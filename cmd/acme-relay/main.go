// Package main is the entry point for the acme-relay server.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"

	"github.com/focalcrest/acme-relay/internal/acme"
	"github.com/focalcrest/acme-relay/internal/config"
	"github.com/focalcrest/acme-relay/internal/dns"
	"github.com/focalcrest/acme-relay/internal/handler"
	"github.com/focalcrest/acme-relay/internal/middleware"
	"github.com/focalcrest/acme-relay/internal/storage"
)

func main() {
	// Load configuration
	cfg, err := config.Load("acme-relay.yaml")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize storage
	store, err := storage.NewFilesystemStorage(cfg.Storage.Path)
	if err != nil {
		log.Fatalf("Failed to initialize storage: %v", err)
	}

	// Override recursive resolvers used for SOA-based zone lookup
	// (needed for split-horizon DNS where internal resolver disagrees with public).
	// AddRecursiveNameservers returns a ChallengeOption closure that mutates the
	// package-level resolver list when invoked; calling it with a nil Challenge
	// is enough because the closure ignores its argument.
	if len(cfg.DNS.RecursiveNameservers) > 0 {
		if err := dns01.AddRecursiveNameservers(cfg.DNS.RecursiveNameservers)(nil); err != nil {
			log.Fatalf("Failed to set recursive nameservers: %v", err)
		}
	}

	// Export DNS provider credentials as env vars; lego's per-provider
	// constructors read them through their normal env paths.
	// Uppercase the keys because viper lowercases yaml keys on parse.
	for k, v := range cfg.DNS.Credentials {
		envKey := strings.ToUpper(k)
		if err := os.Setenv(envKey, v); err != nil {
			log.Fatalf("Failed to set credential env %s: %v", envKey, err)
		}
	}

	// Initialize DNS provider from our supported registry.
	if cfg.DNS.Provider == "" {
		log.Fatal("dns.provider is required")
	}
	dnsProvider, err := dns.NewProvider(cfg.DNS.Provider)
	if err != nil {
		log.Fatalf("Failed to initialize DNS provider: %v", err)
	}

	// Initialize ACME relay
	relay, err := acme.NewRelay(
		cfg.ACME.Email,
		cfg.GetDirectoryURL(),
		dnsProvider,
		store,
	)
	if err != nil {
		log.Fatalf("Failed to initialize ACME relay: %v", err)
	}

	// Direct DNS TXT manipulation API is AliDNS-specific; only enable it
	// when running with the alidns provider.
	var dnsAPIHandler *handler.DNSAPIHandler
	if cfg.DNS.Provider == "alidns" {
		// Read from env after credentials map was exported above; this
		// keeps the source of truth identical to what lego itself reads.
		txtManager, err := dns.NewTXTManager(
			os.Getenv("ALICLOUD_ACCESS_KEY"),
			os.Getenv("ALICLOUD_SECRET_KEY"),
			os.Getenv("ALICLOUD_REGION_ID"),
		)
		if err != nil {
			log.Fatalf("Failed to initialize TXT manager: %v", err)
		}
		dnsAPIHandler = handler.NewDNSAPIHandler(txtManager)
	}

	// Initialize nonce service and ID generator
	nonceSvc := acme.NewNonceService()
	maxOrder, maxAuthz, maxAccount := store.MaxIDs()
	maxID := maxOrder
	if maxAuthz > maxID {
		maxID = maxAuthz
	}
	if maxAccount > maxID {
		maxID = maxAccount
	}
	idGen := acme.NewIDGenerator(maxID)

	// Start nonce cleanup
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	nonceSvc.StartCleanup(ctx)

	// Determine base URL
	baseURL := cfg.Server.BaseURL
	if baseURL == "" {
		scheme := "http"
		baseURL = scheme + "://" + cfg.Server.Address()
	}

	// Initialize handlers
	certHandler := handler.NewCertificateHandler(relay)
	acmeHandler := handler.NewACMEHandler(store, relay, nonceSvc, idGen, baseURL)

	// Set up router
	r := chi.NewRouter()

	// Middleware
	r.Use(chimw.Logger)
	r.Use(chimw.Recoverer)
	r.Use(chimw.Timeout(120 * time.Second))

	// Legacy REST API routes
	r.Route("/", func(r chi.Router) {
		r.Get("/health", certHandler.HealthCheck)
		r.Post("/certificate", certHandler.RequestCertificate)
		r.Get("/certificate/{domain}", certHandler.GetCertificate)
		r.Post("/renew/{domain}", certHandler.RenewCertificate)
	})

	// RFC 8555 ACME routes
	r.Route("/acme", func(r chi.Router) {
		r.Get("/directory", acmeHandler.Directory)
		r.Head("/new-nonce", acmeHandler.NewNonce)
		r.Get("/new-nonce", acmeHandler.NewNonce)

		// new-account uses JWK-based auth (no existing account)
		r.With(acme.JWSWithJWKMiddleware(nonceSvc)).Post("/new-account", acmeHandler.NewAccount)

		// All other endpoints use KID-based auth
		r.Route("/", func(r chi.Router) {
			r.Use(acme.JWSMiddleware(nonceSvc, store.GetAccountByKIDURL))

			r.Post("/new-order", acmeHandler.NewOrder)
			r.Post("/order/{id}", acmeHandler.GetOrder)
			r.Post("/order/{id}/finalize", acmeHandler.FinalizeOrder)
			r.Post("/authz/{id}", acmeHandler.GetAuthorization)
			r.Post("/challenge/{authzID}/{chalID}", acmeHandler.HandleChallenge)
			r.Post("/certificate/{orderID}", acmeHandler.GetCertificate)
		})
	})

	// DNS API routes (token auth) — only when AliDNS is configured.
	if dnsAPIHandler != nil {
		r.Route("/api/v1", func(r chi.Router) {
			tokenSet := cfg.TokenSet()
			r.Use(middleware.APIKeyAuth(tokenSet))
			r.Post("/dns/txt/add", dnsAPIHandler.AddTXT)
			r.Post("/dns/txt/remove", dnsAPIHandler.RemoveTXT)
		})
	}

	// Create server
	srv := &http.Server{
		Addr:         cfg.Server.Address(),
		Handler:      r,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 120 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in goroutine
	go func() {
		log.Printf("Starting acme-relay server on %s", cfg.Server.Address())
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	// Graceful shutdown with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exited")
}
