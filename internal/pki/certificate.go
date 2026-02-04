package pki

import (
	"crypto/x509"
	"math/big"
)

type Certificate struct {
	SerialNumber *big.Int
	X509Cert     *x509.Certificate
	PEM          []byte
}
