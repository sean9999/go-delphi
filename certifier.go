package delphi

import "crypto"

// a Verifier can verify that a signature is valid
type Verifier interface {
	Verify(pub crypto.PublicKey, digest []byte, sig []byte) bool
}

// a Certifier can produce and verify signatures
type Certifier interface {
	crypto.PrivateKey
	crypto.Signer
	Verifier
}
