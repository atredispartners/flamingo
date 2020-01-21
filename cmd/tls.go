package cmd

// Derived from https://github.com/Shyp/generate-tls-cert/

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	log "github.com/sirupsen/logrus"
	"math/big"
	"net"
	"strings"
	"time"
)

func generateTLSCertificate() {
	orgName := params.TLSOrgName
	hosts := strings.Split(params.TLSName, ",")
	notBefore := time.Now()
	notAfter := notBefore.Add(time.Hour * 24 * 365)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("failed to generate tls serial number: %s", err)
	}

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("failed to generate P256 key: %s", err)
	}

	rootTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{orgName},
			CommonName:   "Root CA",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &rootTemplate, &rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		log.Fatalf("failed to generate certificate: %s", err)
	}

	rootCert := derBytes

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("failed to generate leaf P256 key: %s", err)
	}

	serialNumber, err = rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("failed to generate serial number: %s", err)
	}
	leafTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{orgName},
			CommonName:   hosts[0],
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			leafTemplate.IPAddresses = append(leafTemplate.IPAddresses, ip)
		} else {
			leafTemplate.DNSNames = append(leafTemplate.DNSNames, h)
		}
	}

	derBytes, err = x509.CreateCertificate(rand.Reader, &leafTemplate, &rootTemplate, &leafKey.PublicKey, rootKey)
	if err != nil {
		log.Fatalf("failed to generate leaf certificate: %s", err)
	}
	leafCert := derBytes

	_ = rootCert

	params.TLSCertData = certToPEM(leafCert)
	params.TLSKeyData = keyToPEM(leafKey)
}

func keyToPEM(key *ecdsa.PrivateKey) string {
	var pemBytes bytes.Buffer
	b, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		log.Fatalf("failed to marshal ECDSA private key: %v", err)
	}
	if err := pem.Encode(&pemBytes, &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}); err != nil {
		log.Fatalf("failed to PEM encode ECDSA private key: %s", err)
	}
	return string(pemBytes.Bytes())
}

func certToPEM(derBytes []byte) string {
	var pemBytes bytes.Buffer
	if err := pem.Encode(&pemBytes, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		log.Fatalf("failed to PEM encode certificate: %s", err)
	}
	return string(pemBytes.Bytes())
}
