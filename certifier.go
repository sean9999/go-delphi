package delphi

import "crypto"

type Verifier interface {
	Verify(pub crypto.PublicKey, msg []byte, sig []byte) bool
}

// a Certifier can produce and verify signatures
type Certifier interface {
	crypto.PrivateKey
	crypto.Signer
	Verifier
}
