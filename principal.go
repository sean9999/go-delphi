package delphi

import (
	"crypto"
	"crypto/ecdh"
	"io"
)

type CryptOpts struct {
	Nonce []byte
	AAED  []byte
}

var _ Principal = (principal)(principal{})

type Encrypter interface {
	Encrypt(msg []byte, recipient crypto.PublicKey, opts any) ([]byte, error)
}

type Principal interface {
	Encrypter
	crypto.Decrypter
	crypto.PrivateKey
}

type principal struct {
	pub  *ecdh.PublicKey
	priv *ecdh.PrivateKey
}

func (p principal) Encrypt(msg []byte, recipient crypto.PublicKey, opts any) ([]byte, error) {
	return nil, ErrNotImplemented
}

func (p principal) Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	return nil, ErrNotImplemented
}

func (p principal) Public() crypto.PublicKey {
	return p.pub
}

func (p principal) Equal(p2 crypto.PublicKey) bool {
	return p.priv.Equal(p2)
}

func NewPrincipal(rand io.Reader) principal {
	ed := ecdh.X25519()
	priv, err := ed.GenerateKey(rand)
	if err != nil {
		panic(err)
	}
	pub := priv.PublicKey()
	return principal{
		pub:  pub,
		priv: priv,
	}
}

func (principal) From(b []byte) principal {
	ed := ecdh.X25519()
	priv, err := ed.NewPrivateKey(b)
	if err != nil {
		panic(err)
	}
	return principal{
		pub:  priv.PublicKey(),
		priv: priv,
	}
}
