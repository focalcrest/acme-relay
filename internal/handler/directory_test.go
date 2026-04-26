package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"acme-relay/internal/acme"
	"acme-relay/internal/storage"
)

func setupTestACMEHandler(t *testing.T) (*ACMEHandler, *storage.FilesystemStorage) {
	t.Helper()
	dir := t.TempDir()
	store, err := storage.NewFilesystemStorage(dir)
	if err != nil {
		t.Fatalf("failed to create storage: %v", err)
	}
	nonceSvc := acme.NewNonceService()
	idGen := acme.NewIDGenerator(0)
	h := NewACMEHandler(store, nil, nonceSvc, idGen, "https://acme.example.com")
	return h, store
}

func TestDirectory(t *testing.T) {
	h, _ := setupTestACMEHandler(t)

	req := httptest.NewRequest("GET", "/acme/directory", nil)
	rec := httptest.NewRecorder()
	h.Directory(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var dir map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &dir); err != nil {
		t.Fatalf("failed to parse directory: %v", err)
	}

	expected := map[string]string{
		"newNonce":   "https://acme.example.com/acme/new-nonce",
		"newAccount": "https://acme.example.com/acme/new-account",
		"newOrder":   "https://acme.example.com/acme/new-order",
		"revokeCert": "https://acme.example.com/acme/revoke-cert",
		"keyChange":  "https://acme.example.com/acme/key-change",
	}
	for k, v := range expected {
		if dir[k] != v {
			t.Errorf("directory[%q] = %q, want %q", k, dir[k], v)
		}
	}
}

func TestNewNonce_Head(t *testing.T) {
	h, _ := setupTestACMEHandler(t)

	req := httptest.NewRequest("HEAD", "/acme/new-nonce", nil)
	rec := httptest.NewRecorder()
	h.NewNonce(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	nonce := rec.Header().Get("Replay-Nonce")
	if nonce == "" {
		t.Error("Replay-Nonce header should be set")
	}
}

func TestNewNonce_Get(t *testing.T) {
	h, _ := setupTestACMEHandler(t)

	req := httptest.NewRequest("GET", "/acme/new-nonce", nil)
	rec := httptest.NewRecorder()
	h.NewNonce(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	nonce := rec.Header().Get("Replay-Nonce")
	if nonce == "" {
		t.Error("Replay-Nonce header should be set")
	}
	cacheControl := rec.Header().Get("Cache-Control")
	if cacheControl != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cacheControl)
	}
}
