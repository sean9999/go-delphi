package delphi

import (
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

const NonceSize = chacha20poly1305.NonceSize

// A Nonce is a random value with a reasonably high chance of being globally unqiue.
type Nonce [NonceSize]byte

func (nonce Nonce) IsZero() bool {
	for _, b := range nonce {
		if b != 0 {
			return false
		}
	}
	return true
}

func (nonce Nonce) Bytes() []byte {
	return nonce[:]
}

func NewNonce(randy io.Reader) Nonce {
	var n Nonce
	io.ReadFull(randy, n[:])
	return n
}

func NonceFromBytes(b []byte) Nonce {
	var n Nonce
	copy(n[:], b)
	return n
}
