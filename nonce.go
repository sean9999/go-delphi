package delphi

import "golang.org/x/crypto/chacha20poly1305"

const NonceSize = chacha20poly1305.NonceSize

type Nonce [NonceSize]byte

func (nonce Nonce) IsZero() bool {
	for _, b := range nonce {
		if b != 0 {
			return false
		}
	}
	return true
}
