package storage

import (
	"testing"
	"time"

	"acme-relay/internal/acme"
)

func TestFilesystemStorage_SaveAndGetOrder(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFilesystemStorage(dir)
	if err != nil {
		t.Fatalf("NewFilesystemStorage() error: %v", err)
	}

	order := &acme.Order{
		ID:          1,
		Status:      acme.OrderStatusPending,
		Identifiers: []acme.Identifier{{Type: "dns", Value: "example.com"}},
		Authorizations: []string{"http://localhost/acme/authz/1"},
		Finalize:    "http://localhost/acme/order/1/finalize",
		CreatedAt:   time.Now(),
		AccountID:   1,
	}

	if err := store.SaveOrder(order); err != nil {
		t.Fatalf("SaveOrder() error: %v", err)
	}

	got, err := store.GetOrder(1)
	if err != nil {
		t.Fatalf("GetOrder() error: %v", err)
	}
	if got.Status != acme.OrderStatusPending {
		t.Errorf("Status = %q, want pending", got.Status)
	}
	if got.ID != 1 {
		t.Errorf("ID = %d, want 1", got.ID)
	}
}

func TestFilesystemStorage_GetOrder_NotFound(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewFilesystemStorage(dir)

	_, err := store.GetOrder(999)
	if err == nil {
		t.Error("expected error for non-existent order")
	}
}

func TestFilesystemStorage_SaveAndGetAuthorization(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewFilesystemStorage(dir)

	authz := &acme.Authorization{
		ID:         1,
		Status:     acme.AuthzStatusPending,
		Identifier: acme.Identifier{Type: "dns", Value: "example.com"},
		Challenges: []acme.Challenge{
			{Type: acme.ChallengeTypeHTTP01, Token: "token123", Status: acme.ChallengeStatusPending},
		},
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
		AccountID: 1,
	}

	if err := store.SaveAuthorization(authz); err != nil {
		t.Fatalf("SaveAuthorization() error: %v", err)
	}

	got, err := store.GetAuthorization(1)
	if err != nil {
		t.Fatalf("GetAuthorization() error: %v", err)
	}
	if got.Status != acme.AuthzStatusPending {
		t.Errorf("Status = %q, want pending", got.Status)
	}
	if len(got.Challenges) != 1 {
		t.Errorf("Challenges len = %d, want 1", len(got.Challenges))
	}
}

func TestFilesystemStorage_SaveAndGetAccount(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewFilesystemStorage(dir)

	account := &acme.Account{
		ID:        1,
		Status:    acme.AccountStatusValid,
		Email:     "test@example.com",
		PublicKey: "thumbprint123",
		JWKJSON:   `{"kty":"EC","crv":"P-256"}`,
		CreatedAt: time.Now(),
	}

	if err := store.SaveAccount(account); err != nil {
		t.Fatalf("SaveAccount() error: %v", err)
	}

	got, err := store.GetAccount(1)
	if err != nil {
		t.Fatalf("GetAccount() error: %v", err)
	}
	if got.Email != "test@example.com" {
		t.Errorf("Email = %q, want test@example.com", got.Email)
	}
}

func TestFilesystemStorage_GetAccountByJWK(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewFilesystemStorage(dir)

	account := &acme.Account{
		ID:        1,
		Status:    acme.AccountStatusValid,
		PublicKey: "unique-thumbprint",
		JWKJSON:   `{"kty":"EC"}`,
		CreatedAt: time.Now(),
	}
	store.SaveAccount(account)

	got, err := store.GetAccountByJWK("unique-thumbprint")
	if err != nil {
		t.Fatalf("GetAccountByJWK() error: %v", err)
	}
	if got.ID != 1 {
		t.Errorf("ID = %d, want 1", got.ID)
	}

	_, err = store.GetAccountByJWK("nonexistent")
	if err == nil {
		t.Error("expected error for non-existent JWK")
	}
}

func TestFilesystemStorage_MaxIDs(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewFilesystemStorage(dir)

	store.SaveOrder(&acme.Order{ID: 5, CreatedAt: time.Now()})
	store.SaveOrder(&acme.Order{ID: 10, CreatedAt: time.Now()})
	store.SaveAuthorization(&acme.Authorization{ID: 3, ExpiresAt: time.Now().Add(time.Hour)})
	store.SaveAccount(&acme.Account{ID: 7, CreatedAt: time.Now()})

	orderID, authzID, accountID := store.MaxIDs()
	if orderID != 10 {
		t.Errorf("max order ID = %d, want 10", orderID)
	}
	if authzID != 3 {
		t.Errorf("max authz ID = %d, want 3", authzID)
	}
	if accountID != 7 {
		t.Errorf("max account ID = %d, want 7", accountID)
	}
}

func TestFilesystemStorage_GetAccountByKIDURL(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewFilesystemStorage(dir)

	store.SaveAccount(&acme.Account{ID: 42, Status: acme.AccountStatusValid, CreatedAt: time.Now()})

	got, err := store.GetAccountByKIDURL("https://acme.example.com/acme/acct/42")
	if err != nil {
		t.Fatalf("GetAccountByKIDURL() error: %v", err)
	}
	if got.ID != 42 {
		t.Errorf("ID = %d, want 42", got.ID)
	}

	_, err = store.GetAccountByKIDURL("invalid-url")
	if err == nil {
		t.Error("expected error for invalid KID URL")
	}
}

func TestFilesystemStorage_Reload(t *testing.T) {
	dir := t.TempDir()
	store1, _ := NewFilesystemStorage(dir)

	store1.SaveOrder(&acme.Order{ID: 1, Status: acme.OrderStatusPending, CreatedAt: time.Now()})
	store1.SaveAccount(&acme.Account{ID: 1, Status: acme.AccountStatusValid, CreatedAt: time.Now()})

	// Create a new storage instance that should load from disk
	store2, _ := NewFilesystemStorage(dir)

	order, err := store2.GetOrder(1)
	if err != nil {
		t.Fatalf("GetOrder after reload error: %v", err)
	}
	if order.Status != acme.OrderStatusPending {
		t.Errorf("Status after reload = %q, want pending", order.Status)
	}

	account, err := store2.GetAccount(1)
	if err != nil {
		t.Fatalf("GetAccount after reload error: %v", err)
	}
	if account.Status != acme.AccountStatusValid {
		t.Errorf("Status after reload = %q, want valid", account.Status)
	}
}
