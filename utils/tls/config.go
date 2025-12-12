package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
)

type TLSConfig struct {
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
	CA   string `yaml:"ca"`
}

func loadCertAndCA(tlsConfig TLSConfig) (tls.Certificate, *x509.CertPool, error) {
	cert, err := tls.X509KeyPair([]byte(tlsConfig.Cert), []byte(tlsConfig.Key))
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("loading keypair: %w", err)
	}

	certPool := x509.NewCertPool()
	if tlsConfig.CA != "" {
		if !certPool.AppendCertsFromPEM([]byte(tlsConfig.CA)) {
			log.Fatal("failed to append CA cert")
		}
	}

	return cert, certPool, nil
}

func LoadServerTLSConfig(tlsCertKey TLSConfig) (*tls.Config, error) {
	cert, certPool, err := loadCertAndCA(tlsCertKey)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	tlsConfig.ClientCAs = certPool
	tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert

	return tlsConfig, nil
}

func LoadClientTLSConfig(tlsCertKey TLSConfig) (*tls.Config, error) {
	cert, certPool, err := loadCertAndCA(tlsCertKey)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      certPool,
	}, nil
}
