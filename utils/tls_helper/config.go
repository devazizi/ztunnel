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
		ClientCAs:    certPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,

		// Only allow TLS 1.2 and TLS 1.3
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,

		// Strong ciphers for TLS 1.2 (TLS 1.3 ciphers are predefined)
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},

		// Strong elliptic curves
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
		},

		// Disable session tickets if not needed
		SessionTicketsDisabled: true,
	}

	// Optional: enforce strict client certificate verification
	tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		// Custom logic if needed, otherwise default verification is enough
		return nil
	}

	return tlsConfig, nil
}

func LoadClientTLSConfig(tlsCertKey TLSConfig) (*tls.Config, error) {
	cert, certPool, err := loadCertAndCA(tlsCertKey)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      certPool,

		// Enforce TLS 1.2 and 1.3 only
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,

		// Prefer strong cipher suites (for TLS 1.2)
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},

		// Strong elliptic curves for key exchange
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
		},

		// Disable insecure renegotiation
		Renegotiation: tls.RenegotiateNever,

		// Optional: verify server certificate explicitly if needed
		VerifyConnection: func(cs tls.ConnectionState) error {
			// You can add custom certificate verification logic here
			return nil
		},
	}

	return tlsConfig, nil
}
