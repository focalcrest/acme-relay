// Package storage provides certificate persistence.
package storage

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/focalcrest/acme-relay/internal/acme"
	"github.com/focalcrest/acme-relay/pkg/types"
)

// FilesystemStorage implements certificate storage on disk.
type FilesystemStorage struct {
	basePath       string
	mu             sync.RWMutex
	orders         map[int64]*acme.Order
	authorizations map[int64]*acme.Authorization
	accounts       map[int64]*acme.Account
}

// NewFilesystemStorage creates a new filesystem-based storage.
func NewFilesystemStorage(basePath string) (*FilesystemStorage, error) {
	if err := os.MkdirAll(basePath, 0700); err != nil {
		return nil, fmt.Errorf("failed to create storage directory: %w", err)
	}

	store := &FilesystemStorage{
		basePath:       basePath,
		orders:         make(map[int64]*acme.Order),
		authorizations: make(map[int64]*acme.Authorization),
		accounts:       make(map[int64]*acme.Account),
	}

	store.load()
	return store, nil
}

// Store saves a certificate to disk.
func (s *FilesystemStorage) Store(domain string, cert *types.Certificate) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	certPath := s.certPath(domain)
	metadataPath := s.metadataPath(domain)

	if err := os.WriteFile(certPath, []byte(cert.Certificate), 0600); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	data, err := json.Marshal(cert)
	if err != nil {
		return err
	}
	if err := os.WriteFile(metadataPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write metadata: %w", err)
	}

	return nil
}

// Get retrieves a certificate from disk.
func (s *FilesystemStorage) Get(domain string) (*types.Certificate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	metadataPath := s.metadataPath(domain)
	data, err := os.ReadFile(metadataPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("certificate not found for domain: %s", domain)
		}
		return nil, fmt.Errorf("failed to read certificate metadata: %w", err)
	}

	var cert types.Certificate
	if err := json.Unmarshal(data, &cert); err != nil {
		return nil, fmt.Errorf("failed to parse certificate metadata: %w", err)
	}

	return &cert, nil
}

// Exists checks if a certificate exists for a domain.
func (s *FilesystemStorage) Exists(domain string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	_, err := os.Stat(s.metadataPath(domain))
	return err == nil
}

// Delete removes a certificate from disk.
func (s *FilesystemStorage) Delete(domain string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	certPath := s.certPath(domain)
	metadataPath := s.metadataPath(domain)

	if err := os.Remove(certPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete certificate: %w", err)
	}
	if err := os.Remove(metadataPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete metadata: %w", err)
	}

	return nil
}

// List returns all stored certificate domains.
func (s *FilesystemStorage) List() ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entries, err := os.ReadDir(s.basePath)
	if err != nil {
		return nil, fmt.Errorf("failed to list storage: %w", err)
	}

	var domains []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasPrefix(name, "order_") || strings.HasPrefix(name, "authz_") || strings.HasPrefix(name, "account_") {
			continue
		}
		if filepath.Ext(name) == ".json" {
			domain := name[:len(name)-5]
			domains = append(domains, domain)
		}
	}

	return domains, nil
}

// SaveOrder saves an order.
func (s *FilesystemStorage) SaveOrder(order *acme.Order) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.orders[order.ID] = order
	data, err := json.Marshal(order)
	if err != nil {
		return err
	}
	path := filepath.Join(s.basePath, fmt.Sprintf("order_%d.json", order.ID))
	return os.WriteFile(path, data, 0600)
}

// GetOrder retrieves an order by ID.
func (s *FilesystemStorage) GetOrder(id int64) (*acme.Order, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if order, ok := s.orders[id]; ok {
		return order, nil
	}
	return nil, fmt.Errorf("order not found: %d", id)
}

// SaveAuthorization saves an authorization.
func (s *FilesystemStorage) SaveAuthorization(auth *acme.Authorization) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.authorizations[auth.ID] = auth
	data, err := json.Marshal(auth)
	if err != nil {
		return err
	}
	path := filepath.Join(s.basePath, fmt.Sprintf("authz_%d.json", auth.ID))
	return os.WriteFile(path, data, 0600)
}

// GetAuthorization retrieves an authorization by ID.
func (s *FilesystemStorage) GetAuthorization(id int64) (*acme.Authorization, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if auth, ok := s.authorizations[id]; ok {
		return auth, nil
	}
	return nil, fmt.Errorf("authorization not found: %d", id)
}

// SaveAccount saves an account.
func (s *FilesystemStorage) SaveAccount(account *acme.Account) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.accounts[account.ID] = account
	data, err := json.Marshal(account)
	if err != nil {
		return err
	}
	path := filepath.Join(s.basePath, fmt.Sprintf("account_%d.json", account.ID))
	return os.WriteFile(path, data, 0600)
}

// GetAccount retrieves an account by ID.
func (s *FilesystemStorage) GetAccount(id int64) (*acme.Account, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if account, ok := s.accounts[id]; ok {
		return account, nil
	}
	return nil, fmt.Errorf("account not found: %d", id)
}

// GetAccountByJWK finds an account by JWK thumbprint.
func (s *FilesystemStorage) GetAccountByJWK(jwkThumbprint string) (*acme.Account, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, account := range s.accounts {
		if account.PublicKey == jwkThumbprint && account.Status == acme.AccountStatusValid {
			return account, nil
		}
	}
	return nil, fmt.Errorf("account not found for JWK thumbprint: %s", jwkThumbprint)
}

// MaxIDs returns the maximum IDs seen in storage, for ID generator seeding.
func (s *FilesystemStorage) MaxIDs() (orderID, authzID, accountID int64) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for id := range s.orders {
		if id > orderID {
			orderID = id
		}
	}
	for id := range s.authorizations {
		if id > authzID {
			authzID = id
		}
	}
	for id := range s.accounts {
		if id > accountID {
			accountID = id
		}
	}
	return
}

// GetAccountByKIDURL retrieves an account by its KID URL path (e.g., "/acme/acct/1").
func (s *FilesystemStorage) GetAccountByKIDURL(kidURL string) (*acme.Account, error) {
	// Extract account ID from URL like "http://host/acme/acct/1" or "/acme/acct/1"
	parts := strings.Split(kidURL, "/")
	var idStr string
	for i, p := range parts {
		if p == "acct" && i+1 < len(parts) {
			idStr = parts[i+1]
			break
		}
	}
	if idStr == "" {
		return nil, fmt.Errorf("invalid kid URL: %s", kidURL)
	}
	var id int64
	if _, err := fmt.Sscanf(idStr, "%d", &id); err != nil {
		return nil, fmt.Errorf("invalid account ID in kid URL: %s", idStr)
	}
	return s.GetAccount(id)
}

func (s *FilesystemStorage) load() {
	entries, err := os.ReadDir(s.basePath)
	if err != nil {
		return
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		data, err := os.ReadFile(filepath.Join(s.basePath, name))
		if err != nil {
			continue
		}

		if strings.HasPrefix(name, "order_") {
			var order acme.Order
			if json.Unmarshal(data, &order) == nil {
				s.orders[order.ID] = &order
			}
		} else if strings.HasPrefix(name, "authz_") {
			var auth acme.Authorization
			if json.Unmarshal(data, &auth) == nil {
				s.authorizations[auth.ID] = &auth
			}
		} else if strings.HasPrefix(name, "account_") {
			var account acme.Account
			if json.Unmarshal(data, &account) == nil {
				s.accounts[account.ID] = &account
			}
		}
	}
}

// ParseExpiresAt extracts the expiration time from a PEM certificate.
func ParseExpiresAt(pemData string) (time.Time, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return time.Time{}, fmt.Errorf("failed to decode PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert.NotAfter, nil
}

func (s *FilesystemStorage) certPath(domain string) string {
	return filepath.Join(s.basePath, domain+".pem")
}

func (s *FilesystemStorage) metadataPath(domain string) string {
	return filepath.Join(s.basePath, domain+".json")
}
