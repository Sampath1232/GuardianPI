// Guardian Pi — Secure Transport (mTLS-capable HTTP client)
package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/guardianpi/edge-agent/internal/config"
)

// SecureClient wraps http.Client with mTLS and API key auth
type SecureClient struct {
	client    *http.Client
	serverURL string
	apiKey    string
}

// NewSecureClient creates a TLS-configured HTTP client
func NewSecureClient(cfg *config.AgentConfig) *SecureClient {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	// Load mTLS certificates if provided
	if cfg.ClientCertPath != "" && cfg.ClientKeyPath != "" {
		cert, err := tls.LoadX509KeyPair(cfg.ClientCertPath, cfg.ClientKeyPath)
		if err == nil {
			tlsConfig.Certificates = []tls.Certificate{cert}
		}
	}

	// Load CA certificate for server verification
	if cfg.CACertPath != "" {
		caCert, err := os.ReadFile(cfg.CACertPath)
		if err == nil {
			pool := x509.NewCertPool()
			pool.AppendCertsFromPEM(caCert)
			tlsConfig.RootCAs = pool
		}
	}

	transport := &http.Transport{
		TLSClientConfig:     tlsConfig,
		MaxIdleConns:        10,
		IdleConnTimeout:     30 * time.Second,
		DisableCompression:  false,
		MaxConnsPerHost:     5,
	}

	return &SecureClient{
		client: &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		},
		serverURL: cfg.ServerURL,
		apiKey:    cfg.APIKey,
	}
}

// Post sends a JSON POST request with API key authentication
func (c *SecureClient) Post(ctx context.Context, path string, body []byte) ([]byte, error) {
	url := c.serverURL + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", c.apiKey)
	req.Header.Set("User-Agent", "GuardianPi-EdgeAgent/2.0")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("server error %d: %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}
