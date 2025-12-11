package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"gopkg.in/yaml.v3"
)

type Config struct {
	LDAP struct {
		URL          string `yaml:"url"`
		BindDN       string `yaml:"bind_dn"`
		BindPassword string `yaml:"bind_password"`
		BaseDN       string `yaml:"base_dn"`
	} `yaml:"ldap"`
	OrganizationName string `yaml:"organizationName"`
	CA               struct {
		Root struct {
			CN            string `yaml:"cn"`
			ValidityYears int    `yaml:"validity_years"`
		} `yaml:"root"`
		Intermediate struct {
			CN            string `yaml:"cn"`
			ValidityYears int    `yaml:"validity_years"`
		} `yaml:"intermediate"`
	} `yaml:"ca"`

	ServerCert struct {
		ValidityYears int      `yaml:"validity_years"`
		DNSSans       []string `yaml:"dns_sans"`
		IPSans        []string `yaml:"ip_sans"`
	} `yaml:"server_cert"`

	ClientCert struct {
		ValidityYears int `yaml:"validity_years"`
	} `yaml:"client_cert"`
}

func loadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func generatePrivateKey(bits int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, bits)
}

func savePEM(filename, blockType string, derBytes []byte) error {
	file, err := os.Create(fmt.Sprintf("certs/%s", filename))
	if err != nil {
		return err
	}
	defer file.Close()
	return pem.Encode(file, &pem.Block{Type: blockType, Bytes: derBytes})
}

func loadCertificate(filename string) (*x509.Certificate, error) {
	data, err := os.ReadFile(fmt.Sprintf("certs/%s", filename))
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM in %s", filename)
	}
	return x509.ParseCertificate(block.Bytes)
}

func loadPrivateKey(filename string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(fmt.Sprintf("certs/%s", filename))
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM in %s", filename)
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func createCertificate(template, parent *x509.Certificate, pub any, priv any) (*x509.Certificate, error) {
	derBytes, err := x509.CreateCertificate(rand.Reader, template, parent, pub, priv)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(derBytes)
}

func cmdRootCA(cfg *Config) {
	priv, err := generatePrivateKey(4096)
	if err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   cfg.CA.Root.CN,
			Organization: []string{cfg.OrganizationName},
		},
		NotBefore:             time.Now().AddDate(0, 0, -1),
		NotAfter:              time.Now().AddDate(cfg.CA.Root.ValidityYears, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
	}

	cert, err := createCertificate(template, template, &priv.PublicKey, priv)
	if err != nil {
		log.Fatalf("Failed to create cert: %v", err)
	}

	savePEM("rootCA.pem", "CERTIFICATE", cert.Raw)
	savePEM("rootCA.key", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(priv))
	fmt.Println("✓ Root CA generated: rootCA.pem / rootCA.key")
}

func cmdIntermediateCA(cfg *Config) {
	rootCert, err := loadCertificate("rootCA.pem")
	if err != nil {
		log.Fatalf("Load rootCA.pem: %v", err)
	}
	rootKey, err := loadPrivateKey("rootCA.key")
	if err != nil {
		log.Fatalf("Load rootCA.key: %v", err)
	}

	priv, err := generatePrivateKey(4096)
	if err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   cfg.CA.Intermediate.CN,
			Organization: []string{cfg.OrganizationName},
		},
		NotBefore:             time.Now().AddDate(0, 0, -1),
		NotAfter:              time.Now().AddDate(cfg.CA.Intermediate.ValidityYears, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	cert, err := createCertificate(template, rootCert, &priv.PublicKey, rootKey)
	if err != nil {
		log.Fatalf("Failed to create cert: %v", err)
	}

	savePEM("intermediateCA.pem", "CERTIFICATE", cert.Raw)
	savePEM("intermediateCA.key", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(priv))
	fmt.Println("✓ Intermediate CA generated: intermediateCA.pem / intermediateCA.key")
}

func cmdServer(cfg *Config) {
	interCert, err := loadCertificate("intermediateCA.pem")
	if err != nil {
		log.Fatalf("Load intermediateCA.pem: %v", err)
	}
	interKey, err := loadPrivateKey("intermediateCA.key")
	if err != nil {
		log.Fatalf("Load intermediateCA.key: %v", err)
	}

	priv, err := generatePrivateKey(2048)
	if err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}

	var ips []net.IP
	for _, ipStr := range cfg.ServerCert.IPSans {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			log.Fatalf("Invalid IP: %s", ipStr)
		}
		ips = append(ips, ip)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   cfg.ServerCert.DNSSans[0],
			Organization: []string{cfg.OrganizationName},
		},
		NotBefore:   time.Now().AddDate(0, 0, -1),
		NotAfter:    time.Now().AddDate(cfg.ServerCert.ValidityYears, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    cfg.ServerCert.DNSSans,
		IPAddresses: ips,
	}

	cert, err := createCertificate(template, interCert, &priv.PublicKey, interKey)
	if err != nil {
		log.Fatalf("Failed to create cert: %v", err)
	}

	savePEM("server.pem", "CERTIFICATE", cert.Raw)
	savePEM("server.key", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(priv))
	fmt.Println("✓ LDAP Server certificate generated: server.pem / server.key")
	fmt.Printf("  DNS SANs: %s\n", strings.Join(cfg.ServerCert.DNSSans, ", "))
	if len(ips) > 0 {
		fmt.Printf("  IP SANs: %s\n", strings.Join(cfg.ServerCert.IPSans, ", "))
	}
}

func getLDAPUser(cn string, cfg *Config) (*ldap.Entry, error) {
	l, err := ldap.DialURL(cfg.LDAP.URL)
	if err != nil {
		return nil, err
	}
	defer l.Close()

	if err := l.Bind(cfg.LDAP.BindDN, cfg.LDAP.BindPassword); err != nil {
		return nil, err
	}

	searchRequest := ldap.NewSearchRequest(
		cfg.LDAP.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(cn=%s)", cn),
		[]string{"cn", "mail", "uid"},
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		return nil, err
	}
	if len(sr.Entries) == 0 {
		return nil, fmt.Errorf("user %s not found", cn)
	}
	return sr.Entries[0], nil
}

func cmdClientCertificate(username string, cfg *Config) {
	interCert, err := loadCertificate("intermediateCA.pem")
	if err != nil {
		log.Fatalf("Load intermediateCA.pem: %v", err)
	}
	interKey, err := loadPrivateKey("intermediateCA.key")
	if err != nil {
		log.Fatalf("Load intermediateCA.key: %v", err)
	}

	user, err := getLDAPUser(username, cfg)
	if err != nil {
		log.Fatalf("LDAP error: %v", err)
	}
	fmt.Printf("✓ LDAP user found: %s <%s>\n", user.GetAttributeValue("cn"), user.GetAttributeValue("mail"))

	priv, err := generatePrivateKey(2048)
	if err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   user.GetAttributeValue("cn"),
			Organization: []string{cfg.OrganizationName},
		},
		NotBefore:   time.Now().AddDate(0, 0, -1),
		NotAfter:    time.Now().AddDate(cfg.ClientCert.ValidityYears, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	cert, err := createCertificate(template, interCert, &priv.PublicKey, interKey)
	if err != nil {
		log.Fatalf("Failed to create client cert: %v", err)
	}

	savePEM(fmt.Sprintf("%s.pem", username), "CERTIFICATE", cert.Raw)
	savePEM(fmt.Sprintf("%s.key", username), "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(priv))
	fmt.Printf("✓ Client certificate generated: %s.pem / %s.key\n", username, username)
}

func cmdCAInfo() {
	files := []string{"rootCA.pem", "intermediateCA.pem"}
	for _, f := range files {
		cert, err := loadCertificate(f)
		if err != nil {
			log.Printf("Error loading %s: %v", f, err)
			continue
		}
		fmt.Printf("File: %s\n", f)
		fmt.Printf("  Subject: %s\n", cert.Subject.String())
		fmt.Printf("  Issuer : %s\n", cert.Issuer.String())
		fmt.Printf("  Serial : %s\n", cert.SerialNumber.String())
		fmt.Printf("  NotBefore: %s\n", cert.NotBefore)
		fmt.Printf("  NotAfter : %s\n\n", cert.NotAfter)
	}
}

func main() {
	certifyConfigFile := flag.String("certify-conf", "certify.yaml", "certify config yaml")
	flag.Parse()
	if *certifyConfigFile == "" {
		fmt.Println("Error: --certify-conf")
		return
	}

	cfg, err := loadConfig(*certifyConfigFile)
	if err != nil {
		log.Fatalf("Failed to load config.yaml: %v", err)
	}

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "rootca":
		cmdRootCA(cfg)
	case "interca":
		cmdIntermediateCA(cfg)
	case "server":
		cmdServer(cfg)
	case "client":
		if len(os.Args) < 3 {
			log.Fatal("Usage: go run main.go client <ldap-username>")
		}
		cmdClientCertificate(os.Args[2], cfg)
	case "cainfo":
		cmdCAInfo()
	default:
		printUsage()
	}
}

func printUsage() {
	fmt.Println("Usage:")
	fmt.Println("go run main.go rootca")
	fmt.Println("go run main.go interca")
	fmt.Println("go run main.go server")
	fmt.Println("go run main.go client <ldap-username>")
	fmt.Println("go run main.go cainfo")
}
