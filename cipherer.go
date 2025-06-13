package delphi

import (
	"crypto"
	"io"
)

type EncrypterOpts = any

type Encrypter interface {
	Encrypt(io.Reader, *Message, KeyPair, EncrypterOpts) error
}

type Decrypter interface {
	Decrypt(*Message, crypto.DecrypterOpts) error
}

// a Cipherer can encrypt and decrypt a [Message]
type Cipherer interface {
	crypto.PrivateKey
	Encrypter
	Decrypter
}
