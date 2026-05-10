package config

import (
	"os"
	"testing"
)

func TestServerConfigAddress(t *testing.T) {
	cfg := ServerConfig{
		Host: "localhost",
		Port: 8080,
	}

	expected := "localhost:8080"
	if cfg.Address() != expected {
		t.Errorf("Address() = %q, want %q", cfg.Address(), expected)
	}
}

func TestGetDirectoryURL(t *testing.T) {
	tests := []struct {
		provider   string
		directory  string
		expected   string
	}{
		{"letsencrypt", "", "https://acme-v02.api.letsencrypt.org/directory"},
		{"LE", "", "https://acme-v02.api.letsencrypt.org/directory"},
		{"staging", "", "https://acme-staging-v02.api.letsencrypt.org/directory"},
		{"custom", "https://custom.example.com/dir", "https://custom.example.com/dir"},
	}

	for _, tt := range tests {
		t.Run(tt.provider, func(t *testing.T) {
			cfg := &Config{
				ACME: ACMEConfig{
					Provider:     tt.provider,
					DirectoryURL: tt.directory,
				},
			}

			result := cfg.GetDirectoryURL()
			if result != tt.expected {
				t.Errorf("GetDirectoryURL() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name      string
		config    Config
		expectErr bool
	}{
		{
			name: "valid config",
			config: Config{
				Server:  ServerConfig{Host: "0.0.0.0", Port: 8080},
				ACME:    ACMEConfig{Provider: "letsencrypt", Email: "test@example.com"},
				DNS:     DNSConfig{Provider: "alidns"},
				Storage: StorageConfig{Type: "filesystem", Path: "/tmp"},
			},
			expectErr: false,
		},
		{
			name: "invalid port",
			config: Config{
				Server:  ServerConfig{Host: "0.0.0.0", Port: 0},
				ACME:    ACMEConfig{Provider: "letsencrypt", Email: "test@example.com"},
				DNS:     DNSConfig{Provider: "alidns"},
				Storage: StorageConfig{Type: "filesystem", Path: "/tmp"},
			},
			expectErr: true,
		},
		{
			name: "missing acme provider",
			config: Config{
				Server:  ServerConfig{Host: "0.0.0.0", Port: 8080},
				ACME:    ACMEConfig{Email: "test@example.com"},
				DNS:     DNSConfig{Provider: "alidns"},
				Storage: StorageConfig{Type: "filesystem", Path: "/tmp"},
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.expectErr {
				t.Errorf("Validate() error = %v, expectErr %v", err, tt.expectErr)
			}
		})
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := Load("nonexistent.yaml")
	if err == nil {
		t.Error("expected error for nonexistent file, got nil")
	}
}

func TestValidate_MissingFields(t *testing.T) {
	tests := []struct {
		name   string
		config Config
	}{
		{
			name: "missing email",
			config: Config{
				Server:  ServerConfig{Host: "0.0.0.0", Port: 8080},
				ACME:    ACMEConfig{Provider: "letsencrypt"},
				DNS:     DNSConfig{Provider: "alidns"},
				Storage: StorageConfig{Type: "filesystem", Path: "/tmp"},
			},
		},
		{
			name: "missing dns provider",
			config: Config{
				Server:  ServerConfig{Host: "0.0.0.0", Port: 8080},
				ACME:    ACMEConfig{Provider: "letsencrypt", Email: "test@example.com"},
				Storage: StorageConfig{Type: "filesystem", Path: "/tmp"},
			},
		},
		{
			name: "missing storage type",
			config: Config{
				Server:  ServerConfig{Host: "0.0.0.0", Port: 8080},
				ACME:    ACMEConfig{Provider: "letsencrypt", Email: "test@example.com"},
				DNS:     DNSConfig{Provider: "alidns"},
				Storage: StorageConfig{Path: "/tmp"},
			},
		},
		{
			name: "missing storage path",
			config: Config{
				Server:  ServerConfig{Host: "0.0.0.0", Port: 8080},
				ACME:    ACMEConfig{Provider: "letsencrypt", Email: "test@example.com"},
				DNS:     DNSConfig{Provider: "alidns"},
				Storage: StorageConfig{Type: "filesystem"},
			},
		},
		{
			name: "port too high",
			config: Config{
				Server:  ServerConfig{Host: "0.0.0.0", Port: 70000},
				ACME:    ACMEConfig{Provider: "letsencrypt", Email: "test@example.com"},
				DNS:     DNSConfig{Provider: "alidns"},
				Storage: StorageConfig{Type: "filesystem", Path: "/tmp"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.config.Validate(); err == nil {
				t.Error("expected validation error, got nil")
			}
		})
	}
}

func TestGetDirectoryURL_DefaultFallback(t *testing.T) {
	cfg := &Config{
		ACME: ACMEConfig{Provider: "https://acme.custom.example.com"},
	}
	got := cfg.GetDirectoryURL()
	if got != "https://acme.custom.example.com" {
		t.Errorf("GetDirectoryURL() = %q, want provider URL as fallback", got)
	}

	cfgStaging := &Config{
		ACME: ACMEConfig{Provider: "letsencrypt-staging"},
	}
	got = cfgStaging.GetDirectoryURL()
	if got != "https://acme-staging-v02.api.letsencrypt.org/directory" {
		t.Errorf("GetDirectoryURL(letsencrypt-staging) = %q, want staging URL", got)
	}
}

func TestLoad_ValidConfig(t *testing.T) {
	// Create a temp config file
	content := `
server:
  host: "127.0.0.1"
  port: 9090
acme:
  provider: "letsencrypt"
  email: "test@example.com"
dns:
  provider: "alidns"
  accessKey: "test-key"
  secretKey: "test-secret"
storage:
  type: "filesystem"
  path: "/tmp/certs"
`
	tmpfile, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write([]byte(content)); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	tmpfile.Close()

	cfg, err := Load(tmpfile.Name())
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Server.Port != 9090 {
		t.Errorf("Server.Port = %d, want 9090", cfg.Server.Port)
	}
	if cfg.ACME.Email != "test@example.com" {
		t.Errorf("ACME.Email = %q, want %q", cfg.ACME.Email, "test@example.com")
	}
}
