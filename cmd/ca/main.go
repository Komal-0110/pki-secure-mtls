package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"pki-secure-mtls/internal/pki"
	"pki-secure-mtls/internal/storage"
	"time"
)

func main() {
	storage := storage.FileSystemStorage{}

	keyPair, err := pki.GenerateRSAKeyPair(4096)
	if err != nil {
		log.Fatal("failed to generate key pair", err)
	}

	// create root ca certificate template
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Go Root CA",
			Organization: []string{"Go PKI Lab"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, 1),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	// self-signed root ca
	certDER, err := x509.CreateCertificate(
		rand.Reader,
		template,
		template,
		&keyPair.PrivateKey.(*rsa.PrivateKey).PublicKey,
		keyPair.PrivateKey,
	)
	if err != nil {
		log.Fatal("failed to self signed root CA", err)
	}

	// encode certificate
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Encode private key
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(keyPair.PrivateKey.(*rsa.PrivateKey)),
	})

	// Save files
	err = storage.SaveCertificate("certs/root/ca.crt.pem", certPEM)
	if err != nil {
		log.Fatal(err)
	}

	err = storage.SaveKey("certs/root/ca.key.pem", keyPEM)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Root CA generated successfully")
}
