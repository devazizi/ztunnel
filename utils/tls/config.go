package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"

	"github.com/goccy/go-yaml"
)

// TLSConfigYAML holds certificate, key, and CA in PEM format
type TLSConfigYAML struct {
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
	CA   string `yaml:"ca"` // optional
}

// loadCertAndCA reads a YAML file and returns the TLS certificate and CertPool for the CA
func loadCertAndCA(path string) (tls.Certificate, *x509.CertPool, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return tls.Certificate{}, nil, err
	}

	var cfg TLSConfigYAML
	if err := yaml.Unmarshal(content, &cfg); err != nil {
		return tls.Certificate{}, nil, err
	}

	// Load certificate + key
	cert, err := tls.X509KeyPair([]byte(cfg.Cert), []byte(cfg.Key))
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("loading keypair: %w", err)
	}

	// Load CA pool
	certPool := x509.NewCertPool()
	if cfg.CA != "" {
		if !certPool.AppendCertsFromPEM([]byte(cfg.CA)) {
			log.Fatal("failed to append CA cert")
		}
	}

	return cert, certPool, nil
}

// LoadServerTLSConfig loads TLS config for a server with optional client verification
func LoadServerTLSConfig(path string, requireClientCert bool) (*tls.Config, error) {
	cert, certPool, err := loadCertAndCA(path)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	if requireClientCert {
		tlsConfig.ClientCAs = certPool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return tlsConfig, nil
}

// LoadClientTLSConfig loads TLS config for a client that verifies the server certificate
func LoadClientTLSConfig(path string) (*tls.Config, error) {
	cert, certPool, err := loadCertAndCA(path)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert}, // optional, only if server requires client cert
		RootCAs:      certPool,                // trust CA for server verification
	}, nil
}
