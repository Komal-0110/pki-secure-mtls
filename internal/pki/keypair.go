package pki

import "crypto"

type KeyPair struct {
	PrivateKey crypto.PrivateKey
	PublicKey  crypto.PublicKey
	Algorithm  string
}
