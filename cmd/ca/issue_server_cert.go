package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"os"
	"time"
)

func issueServerCert() {
	rootCertPEM, err := os.ReadFile("certs/root/ca.crt.pem")
	if err != nil {
		log.Fatal("failed to open root certificate", err)
	}

	rootBlock, _ := pem.Decode(rootCertPEM)

	rootCert, err := x509.ParseCertificate(rootBlock.Bytes)
	if err != nil {
		log.Fatal("failed to parse root certificate", err)
	}

	rootKeyPEM, err := os.ReadFile("certs/root/ca.key.pem")
	if err != nil {
		log.Fatal("failed to open root key", err)
	}

	rootKeyBlock, _ := pem.Decode(rootKeyPEM)

	rootKey, err := x509.ParsePKCS1PrivateKey(rootKeyBlock.Bytes)
	if err != nil {
		log.Fatal("failed to parse root key", err)
	}

	serverKey, err := rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		log.Fatal("failed to generate server key", err)
	}

	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			CommonName:   "secure-server.local",
			Organization: []string{"Go PKI Server"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(0, 0, 10),

		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},

		DNSNames: []string{"localhost"},
		IPAddresses: []net.IP{
			net.ParseIP("127.0.0.1"),
		},
	}

	serverCertDER, err := x509.CreateCertificate(
		rand.Reader, serverTemplate, rootCert, &serverKey.PublicKey, rootKey,
	)
	if err != nil {
		log.Fatal("failed to create server certificate", err)
	}

	serverCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: serverCertDER,
	})

	err = os.WriteFile("certs/server/server.crt.pem", serverCertPEM, 0600)
	if err != nil {
		log.Fatal("failed to write server certificate", err)
	}

	serverKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(serverKey),
	})

	err = os.WriteFile("certs/server/server.key.pem", serverKeyPEM, 0600)
	if err != nil {
		log.Fatal("failed to write server key", err)
	}

	log.Println("✅ Server certificate issued successfully")
}
