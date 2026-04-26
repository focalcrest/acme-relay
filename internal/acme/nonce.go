package acme

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

const (
	nonceTTL       = 1 * time.Hour
	cleanupInterval = 10 * time.Minute
)

// NonceService manages ACME nonces for replay protection.
type NonceService struct {
	mu     sync.RWMutex
	nonces map[string]time.Time
}

// NewNonceService creates a new nonce service.
func NewNonceService() *NonceService {
	return &NonceService{
		nonces: make(map[string]time.Time),
	}
}

// Generate creates a new nonce and stores it.
func (s *NonceService) Generate() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	nonce := base64.RawURLEncoding.EncodeToString(b)

	s.mu.Lock()
	s.nonces[nonce] = time.Now().Add(nonceTTL)
	s.mu.Unlock()

	return nonce, nil
}

// Validate checks that a nonce is valid (exists and not expired), then consumes it.
// Each nonce can only be used once.
func (s *NonceService) Validate(nonce string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	expiry, ok := s.nonces[nonce]
	if !ok {
		return false
	}
	delete(s.nonces, nonce)
	return time.Now().Before(expiry)
}

// StartCleanup runs a background goroutine that purges expired nonces.
func (s *NonceService) StartCleanup(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(cleanupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.purgeExpired()
			}
		}
	}()
}

func (s *NonceService) purgeExpired() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for n, expiry := range s.nonces {
		if now.After(expiry) {
			delete(s.nonces, n)
		}
	}
}
