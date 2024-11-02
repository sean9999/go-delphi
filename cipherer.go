package delphi

import (
	"crypto"
	"crypto/ed25519"
	"io"
)

type EncrypterOpts = any

type Encrypter interface {
	Encrypt(io.Reader, *Message, EncrypterOpts) error
}

type Decrypter interface {
	Decrypt(*Message, ed25519.PrivateKey, crypto.DecrypterOpts) error
}

// a Cipherer can encrypt and decrypt a [message]
type Cipherer interface {
	crypto.PrivateKey
	Encrypter
}
