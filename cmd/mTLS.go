package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/humanjuan/logger"
)

var (
	ORG                         = "HumanJuan by Juan Alejandro"
	CITY                        = "Linares"
	STATE                       = "Maule"
	COUNTRY                     = "Chile"
	EMAIL                       = "juan.alejandro@humanjuan.com"
	CERTIFICATE_DIR             = "./certificates"
	CERTIFICATE_EXPIRATION_DAYS = 365
	CA_CN                       = "HumanJuan Root CA"
	SERVER_CN                   = "Golyn Server"
	CLIENT_CN                   = "Portal HumanJuan Client"
	HOST_IPS                    = []string{"127.0.0.1"}
	DNS_NAMES                   = []string{"portal.humanjuan.local"}
	LOG_NAME                    = "certificates.log"
	LOG_PATH                    = "./logs"
	LOG_LEVEL                   = logger.Level.DEBUG
)

var log *logger.Log

type certConfig struct {
	CommonName   string
	IPAddresses  []net.IP
	DNSNames     []string
	ExtKeyUsage  []x509.ExtKeyUsage
	IsCA         bool
	KeyUsage     x509.KeyUsage
	NotBefore    time.Time
	NotAfter     time.Time
	SerialNumber *big.Int
}

func init() {
	var err error
	log, err = logger.Start(LOG_NAME, LOG_PATH, LOG_LEVEL)
	if err != nil {
		panic(fmt.Sprintf("Error initializing logger: %v", err))
	}
	log.TimestampFormat(logger.TS.Special)
	log.Rotation(40, 4)
}

func main() {
	defer log.Close()

	log.Info("Starting certificate generation")
	if err := os.MkdirAll(CERTIFICATE_DIR, 0755); err != nil {
		log.Error("Directory creation failed %s: %v", CERTIFICATE_DIR, err)
		return
	}

	ips := append(HOST_IPS, generateIPs("192.168.100.", 2, 254)...)

	// Using existing CA
	caCert, caKey, err := loadExistingCA()
	if err != nil {
		log.Info("No existing CA found or error loading CA: %v", err)
		log.Info("Generating new CA certificate")
		caCert, caKey, err = generateCACert()
		if err != nil {
			log.Error("Error generating CA: %v", err)
			return
		}
	} else {
		log.Info("Using existing CA certificate")
	}

	// SERVER
	if err := generateCert("server", caCert, caKey, certConfig{
		CommonName:  SERVER_CN,
		IPAddresses: parseIPs(ips),
		DNSNames:    DNS_NAMES,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		log.Error("Error generating server certificate: %v", err)
		return
	}

	// CLIENT
	if err := generateCert("client", caCert, caKey, certConfig{
		CommonName:  CLIENT_CN,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		log.Error("Error generating client certificate: %v", err)
		return
	}

	log.Info("certificate has been successfully generated in %s", CERTIFICATE_DIR)
}

func generateCACert() (*x509.Certificate, *rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("CA private key generation failed: %v", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("serial number generation failed: %v", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(time.Duration(CERTIFICATE_EXPIRATION_DAYS*10) * 24 * time.Hour) // CA valid for 10 years

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{ORG},
			Country:      []string{COUNTRY},
			Province:     []string{STATE},
			Locality:     []string{CITY},
			CommonName:   CA_CN,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		EmailAddresses:        []string{EMAIL},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("CA Certificate creation failed: %v", err)
	}

	caCert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("CA certificate parsing failed: %v", err)
	}

	// SAVE CA
	if err := saveCertAndKey("ca", derBytes, priv); err != nil {
		return nil, nil, err
	}

	return caCert, priv, nil
}

// Certificate Server or Cliente
func generateCert(name string, caCert *x509.Certificate, caKey *rsa.PrivateKey, config certConfig) error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("error generating private key for %s: %v", name, err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("error generating serial number for %s: %v", name, err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(time.Duration(CERTIFICATE_EXPIRATION_DAYS) * 24 * time.Hour)

	keyUsage := x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
	if config.IsCA {
		keyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{ORG},
			Country:      []string{COUNTRY},
			Province:     []string{STATE},
			Locality:     []string{CITY},
			CommonName:   config.CommonName,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           config.ExtKeyUsage,
		IPAddresses:           config.IPAddresses,
		DNSNames:              config.DNSNames,
		BasicConstraintsValid: true,
		IsCA:                  config.IsCA,
		EmailAddresses:        []string{EMAIL},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, &priv.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("error creating certificate for %s: %v", name, err)
	}

	return saveCertAndKey(name, derBytes, priv)
}

func saveCertAndKey(name string, derBytes []byte, priv *rsa.PrivateKey) error {
	// CERT
	certDir := filepath.Join(CERTIFICATE_DIR, name)
	if err := os.MkdirAll(certDir, 0755); err != nil {
		return fmt.Errorf("directory creation failed %s: %v", certDir, err)
	}
	certFile := filepath.Join(certDir, fmt.Sprintf("%s-cert.pem", name))
	certOut, err := os.Create(certFile)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %v", certFile, err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return err
	}
	if err := certOut.Close(); err != nil {
		return err
	}
	log.Info("Written to ./%s", certFile)

	// PRIVKEY
	keyFile := filepath.Join(certDir, fmt.Sprintf("%s-key.pem", name))
	keyOut, err := os.Create(keyFile)
	if err != nil {
		return fmt.Errorf("error opening %s for writing: %v", keyFile, err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		return err
	}
	if err := keyOut.Close(); err != nil {
		return err
	}
	log.Info("Written to ./%s", keyFile)

	if err := os.Chmod(keyFile, 0600); err != nil {
		return fmt.Errorf("error setting permissions on %s: %v", keyFile, err)
	}

	return nil
}

func loadExistingCA() (*x509.Certificate, *rsa.PrivateKey, error) {
	certPath := filepath.Join(CERTIFICATE_DIR, "ca", "ca-cert.pem")
	keyPath := filepath.Join(CERTIFICATE_DIR, "ca", "ca-key.pem")

	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		return nil, nil, fmt.Errorf("CA certificate not found")
	}
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		return nil, nil, fmt.Errorf("CA private key not found")
	}

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("error reading CA certificate: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("failed to parse CA certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CA certificate: %v", err)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("error reading CA private key: %v", err)
	}
	block, _ = pem.Decode(keyPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("failed to parse CA private key PEM")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CA private key: %v", err)
	}

	return cert, key, nil
}

func generateIPs(base string, start, end int) []string {
	var ips []string
	for i := start; i <= end; i++ {
		ips = append(ips, fmt.Sprintf("%s%d", base, i))
	}
	return ips
}

func parseIPs(ipStrings []string) []net.IP {
	var ips []net.IP
	for _, ipStr := range ipStrings {
		ip := net.ParseIP(ipStr)
		if ip != nil {
			ips = append(ips, ip)
		}
	}
	return ips
}
