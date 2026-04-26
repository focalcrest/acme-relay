// Package config provides configuration management using viper.
package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

// APITokenConfig holds a single API token for DNS API authentication.
type APITokenConfig struct {
	Token       string `mapstructure:"token"`
	Description string `mapstructure:"description"`
}

// Config holds all application configuration.
type Config struct {
	Server    ServerConfig    `mapstructure:"server"`
	ACME      ACMEConfig      `mapstructure:"acme"`
	DNS       DNSConfig       `mapstructure:"dns"`
	Storage   StorageConfig   `mapstructure:"storage"`
	APITokens []APITokenConfig `mapstructure:"apiTokens"`
}

// ServerConfig holds HTTP server settings.
type ServerConfig struct {
	Host    string `mapstructure:"host"`
	Port    int    `mapstructure:"port"`
	BaseURL string `mapstructure:"baseUrl"`
}

// ACMEConfig holds ACME provider settings.
type ACMEConfig struct {
	Provider string `mapstructure:"provider"`
	Email    string `mapstructure:"email"`
	DirectoryURL string `mapstructure:"directoryUrl"`
}

// DNSConfig holds DNS provider settings.
type DNSConfig struct {
	Provider  string `mapstructure:"provider"`
	AccessKey string `mapstructure:"accessKey"`
	SecretKey string `mapstructure:"secretKey"`
	RegionID  string `mapstructure:"regionId"`
}

// StorageConfig holds certificate storage settings.
type StorageConfig struct {
	Type string `mapstructure:"type"`
	Path string `mapstructure:"path"`
}

// TokenSet returns a map of all configured API tokens for fast lookup.
func (c *Config) TokenSet() map[string]bool {
	tokens := make(map[string]bool, len(c.APITokens))
	for _, t := range c.APITokens {
		tokens[t.Token] = true
	}
	return tokens
}

// Address returns the server address string.
func (s ServerConfig) Address() string {
	return fmt.Sprintf("%s:%d", s.Host, s.Port)
}

// Load reads configuration from file and environment variables.
func Load(configPath string) (*Config, error) {
	v := viper.New()

	// Set config file
	v.SetConfigFile(configPath)
	v.SetConfigType("yaml")

	// Environment variable support
	v.SetEnvPrefix("ACME_RELAY")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Read config file
	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Validate required fields
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &cfg, nil
}

// Validate checks that all required configuration is present.
func (c *Config) Validate() error {
	if c.Server.Port <= 0 || c.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", c.Server.Port)
	}
	if c.ACME.Provider == "" {
		return fmt.Errorf("acme provider is required")
	}
	if c.ACME.Email == "" {
		return fmt.Errorf("acme email is required")
	}
	if c.DNS.Provider == "" {
		return fmt.Errorf("dns provider is required")
	}
	if c.Storage.Type == "" {
		return fmt.Errorf("storage type is required")
	}
	if c.Storage.Path == "" {
		return fmt.Errorf("storage path is required")
	}
	return nil
}

// GetDirectoryURL returns the ACME directory URL based on provider.
func (c *Config) GetDirectoryURL() string {
	if c.ACME.DirectoryURL != "" {
		return c.ACME.DirectoryURL
	}
	switch c.ACME.Provider {
	case "letsencrypt", "LE":
		return "https://acme-v02.api.letsencrypt.org/directory"
	case "staging", "letsencrypt-staging":
		return "https://acme-staging-v02.api.letsencrypt.org/directory"
	default:
		return c.ACME.Provider
	}
}
