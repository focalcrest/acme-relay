package acme

import (
	"context"
	"testing"
	"time"
)

func TestNonceService_GenerateAndValidate(t *testing.T) {
	svc := NewNonceService()

	nonce, err := svc.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	if nonce == "" {
		t.Fatal("Generate() returned empty nonce")
	}

	if !svc.Validate(nonce) {
		t.Error("Validate() returned false for valid nonce")
	}
}

func TestNonceService_SingleUse(t *testing.T) {
	svc := NewNonceService()
	nonce, _ := svc.Generate()

	if !svc.Validate(nonce) {
		t.Error("first validation should succeed")
	}
	if svc.Validate(nonce) {
		t.Error("second validation should fail (nonce already consumed)")
	}
}

func TestNonceService_InvalidNonce(t *testing.T) {
	svc := NewNonceService()
	if svc.Validate("nonexistent") {
		t.Error("Validate() should return false for unknown nonce")
	}
}

func TestNonceService_Cleanup(t *testing.T) {
	svc := NewNonceService()

	// Generate a nonce and manually set it as expired
	svc.mu.Lock()
	svc.nonces["expired-nonce"] = time.Now().Add(-1 * time.Hour)
	svc.nonces["valid-nonce"] = time.Now().Add(1 * time.Hour)
	svc.mu.Unlock()

	// Run purge
	svc.purgeExpired()

	svc.mu.RLock()
	_, hasExpired := svc.nonces["expired-nonce"]
	_, hasValid := svc.nonces["valid-nonce"]
	svc.mu.RUnlock()

	if hasExpired {
		t.Error("expired nonce should have been purged")
	}
	if !hasValid {
		t.Error("valid nonce should still exist")
	}
}

func TestNonceService_StartCleanup_StopsOnCancel(t *testing.T) {
	svc := NewNonceService()
	ctx, cancel := context.WithCancel(context.Background())

	svc.StartCleanup(ctx)

	// Generate a nonce before cancel
	nonce, _ := svc.Generate()

	cancel()
	time.Sleep(50 * time.Millisecond) // give goroutine time to exit

	// Service should still work after context cancellation
	if !svc.Validate(nonce) {
		t.Error("Validate should still work after cleanup goroutine stops")
	}
}
