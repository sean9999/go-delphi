package delphi

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding"
	"io"
)

const ByteSize = 128

type CryptOpts struct {
	Nonce []byte
	AAED  []byte
}

// principal implements Principal
var _ Principal = (principal)(principal{})

// a Principal is a holder of a public/private key-pair
// that can perform encryption, decryption, signing, and verifying operations.
type Principal interface {
	Cipherer
	Certifier
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
}

// a principal contains in this order:
// - 32 bytes of private encryption key (ecdh)
// - 32 bytes of public encryption key (ecdh)
// - 32 bytes of private signing key (ed25519)
// - 32 bytes of public signing key (ed25519)
type principal [128]byte

// type notary [64]byte

// func (p principal) MarshalBinary() ([]byte, error) {
// 	return p[:], nil
// }

// func (p principal) UnmarshalBinary(b []byte) error {
// 	if len(b) != ByteSize {
// 		return errors.New("wrong length")
// 	}
// 	copy(p[:], b)
// 	return nil
// }

func (p principal) Sign(randy io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	return nil, ErrNotImplemented
}

func (p principal) Verify(pub crypto.PublicKey, msg []byte, sig []byte) bool {
	return false
}

func (p principal) Encrypt(msg []byte, recipient crypto.PublicKey, opts any) ([]byte, error) {
	return nil, ErrNotImplemented
}

func (p principal) Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	return nil, ErrNotImplemented
}

// func (p principal) byteRange(from, to int) []byte {
// 	return p[from:to]
// }

func (p principal) publicSigningKey() ed25519.PublicKey {
	return ed25519.PublicKey(p[96:])
}

func (p principal) privateSigningKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(p[64:96])
}

func (p principal) privateEncryptionKey() *ecdh.PrivateKey {
	b := p[:64]
	priv, err := ecdh.X25519().NewPrivateKey(b)
	if err != nil {
		panic(err)
	}
	return priv
}

func (p principal) publicEncryptionKey() *ecdh.PublicKey {
	return p.privateEncryptionKey().PublicKey()
}

func (p principal) Public() crypto.PublicKey {
	//	i guess the signing key is most appropriate here?
	return p.publicSigningKey()
}

func (p principal) Equal(p2 crypto.PublicKey) bool {
	//	true if key matches either encryption or signing key
	return p.publicSigningKey().Equal(p2) || p.publicEncryptionKey().Equal(p2)
}

func (p principal) MarshalBinary() ([]byte, error) {
	return p[:], nil
}

func (p principal) UnmarshalBinary(b []byte) error {
	copy(p[:], b)
	return nil
}

func NewPrincipal(randy io.Reader) principal {

	var p principal

	ed := ecdh.X25519()
	//	first 32 bytes
	encryptionPriv, err := ed.GenerateKey(randy)
	if err != nil {
		panic(err)
	}
	//	second 32 bytes
	encryptionPub := encryptionPriv.PublicKey()

	if len(encryptionPriv.Bytes()) != 32 {
		panic("encyption private key wrong length")
	}
	if len(encryptionPub.Bytes()) != 32 {
		panic("encyption public key wrong length")
	}

	copy(p[:32], encryptionPriv.Bytes())
	copy(p[32:64], encryptionPub.Bytes())

	//	priv is 64 bytes and contains the public key
	_, signPriv, err := ed25519.GenerateKey(randy)
	if err != nil {
		panic(err)
	}

	if len(signPriv) != 64 {
		panic("wrong length for signing private key")
	}

	copy(p[64:], signPriv)

	return p
}

func (principal) From(b []byte) principal {

	if len(b) < ByteSize {
		panic("not enough bytes")
	}

	var p principal
	copy(p[:], b)
	return p

}
