package ca

import (
	"crypto/x509"
	"pki-secure-mtls/internal/pki"
	"pki-secure-mtls/internal/storage"
)

type CertificateAuthority struct {
	Certificate *x509.Certificate
	KeyPair     *pki.KeyPair
	Storage     storage.Storage
}
