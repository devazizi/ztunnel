package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/goccy/go-yaml"
)

// TLSConfigYAML represents the YAML structure
type TLSConfigYAML struct {
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
	CA   string `yaml:"ca"` // optional, for client verification
}

//// LoadTLSConfig reads the YAML and returns a *tls.Config for server or client
//func LoadTLSConfig(yamlPath string, requireClientCert bool) (*tls.Config, error) {
//	// Read YAML file
//	data, err := ioutil.ReadFile(yamlPath)
//	if err != nil {
//		return nil, fmt.Errorf("failed to read YAML: %v", err)
//	}
//
//	// Unmarshal YAML
//	var cfg TLSConfigYAML
//	if err := yaml.Unmarshal(data, &cfg); err != nil {
//		return nil, fmt.Errorf("failed to unmarshal YAML: %v", err)
//	}
//
//	// Load server/client certificate
//	cert, err := tls.X509KeyPair([]byte(cfg.Cert), []byte(cfg.Key))
//	if err != nil {
//		return nil, fmt.Errorf("failed to load key pair: %v", err)
//	}
//
//	tlsConf := &tls.Config{
//		Certificates: []tls.Certificate{cert},
//	}
//
//	// If CA is provided, use it for client verification or server verification
//	if cfg.CA != "" {
//		caPool := x509.NewCertPool()
//		if !caPool.AppendCertsFromPEM([]byte(cfg.CA)) {
//			return nil, fmt.Errorf("failed to parse CA certificate")
//		}
//		if requireClientCert {
//			tlsConf.ClientCAs = caPool
//			tlsConf.ClientAuth = tls.RequireAndVerifyClientCert
//		} else {
//			tlsConf.RootCAs = caPool
//		}
//	}
//
//	return tlsConf, nil
//}

func LoadTLSConfig(path string, skipVerify bool) (*tls.Config, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg struct {
		Cert string `yaml:"cert"`
		Key  string `yaml:"key"`
		CA   string `yaml:"ca"`
	}
	if err := yaml.Unmarshal(content, &cfg); err != nil {
		return nil, err
	}

	cert, err := tls.X509KeyPair([]byte(cfg.Cert), []byte(cfg.Key))
	if err != nil {
		return nil, fmt.Errorf("loading keypair: %w", err)
	}

	roots := x509.NewCertPool()
	if ok := roots.AppendCertsFromPEM([]byte(cfg.CA)); !ok {
		return nil, fmt.Errorf("failed to parse root CA")
	}

	return &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            roots,
		InsecureSkipVerify: skipVerify,
	}, nil
}
