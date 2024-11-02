package delphi

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding"
	"errors"
	"fmt"
	"io"
)

const ByteSize = 128

type CryptOpts struct {
	Nonce []byte
	AAED  []byte
}

// principal implements Principal
var _ Principal = (*principal)(nil)

// a Principal is a holder of a public/private key-pair
// that can perform encryption, decryption, signing, and verifying operations.
type Principal interface {
	Cipherer
	Certifier
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
}

/**
 * Layout:
 *	1st 32 bytes:	public	encrpytion key
 *	2nd 32 bytes:	public	signing	key
 *	3rd 32 bytes:	private encryption key
 *	4th 32 bytes:	private signing key
 **/
type principal = keyPair

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

func (p *principal) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	sig := ed25519.Sign(p.privateSigningKey(), digest)
	return sig, nil
}

func (p *principal) Verify(delphiPubKey crypto.PublicKey, digest []byte, sig []byte) bool {
	dpub := delphiPubKey.(key)
	edpub := ed25519.PublicKey(dpub[1][:])
	return ed25519.Verify(edpub, digest, sig)
}

var ErrBadKey = errors.New("bad key")

func (p *principal) Encrypt(randy io.Reader, msg *Message, opts any) error {

	if msg.Encrypted() {
		return fmt.Errorf("%w: already encrypted", ErrDelphi)
	}
	if !msg.Plain() {
		return fmt.Errorf("%w: there is no plain text to encrypt", ErrDelphi)
	}

	if msg.to.IsZero() {
		return fmt.Errorf("%w: recipient: %w", ErrDelphi, ErrBadKey)
	}

	sec, eph, err := generateSharedSecret(msg.to.Encryption().Bytes(), randy)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrDelphi, err)
	}

	msg.ensureNonce(randy)
	msg.ephPubkey = eph

	ciph, err := encrypt(sec, msg.plainText, msg.nonce.Bytes(), msg.headers)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrDelphi, err)
	}

	msg.cipherText = ciph
	msg.plainText = nil

	// sec, err := extractSharedSecret(msg.EphemeralKey(), p.privateEncryptionKey().Bytes(), msg.Recipient().Bytes())
	// if err != nil {
	// 	return err
	// }

	return nil
}

func (p *principal) Decrypt(_ io.Reader, msg *Message, opts crypto.DecrypterOpts) ([]byte, error) {

	sharedSec, err := extractSharedSecret(msg.ephPubkey, p.privateEncryptionKey().Bytes(), p.publicEncryptionKey().Bytes())
	if err != nil {
		return nil, fmt.Errorf("could not decrypt: %w", err)
	}
	plainTxt, err := decrypt(sharedSec, msg.cipherText, msg.nonce[:], msg.headers)
	if err != nil {
		return nil, fmt.Errorf("could not decrypt: %w", err)
	}
	return plainTxt, nil
}

// func (p principal) byteRange(from, to int) []byte {
// 	return p[from:to]
// }

func (p *principal) publicSigningKey() ed25519.PublicKey {
	return ed25519.PublicKey(p[0][1][:])
}

func (p *principal) privateSigningKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(p[1][1][:])
}

func (p *principal) privateEncryptionKey() *ecdh.PrivateKey {
	priv, err := ecdh.X25519().NewPrivateKey(p[1][0][:])
	if err != nil {
		panic(err)
	}
	return priv
}

func (p *principal) publicEncryptionKey() *ecdh.PublicKey {
	return p.privateEncryptionKey().PublicKey()
}

func (p *principal) PublicKey() key {
	return p[0]
}

func (p *principal) privateKey() key {
	return p[1]
}

func (p *principal) Public() crypto.PublicKey {
	//	i guess the signing key is most appropriate here?
	return p[0]
}

func (p *principal) Equal(p2 crypto.PublicKey) bool {
	//	true if key matches either encryption or signing key
	return p.publicSigningKey().Equal(p2) || p.publicEncryptionKey().Equal(p2)
}

func (p *principal) MarshalBinary() ([]byte, error) {
	return p.Bytes(), nil
}

func (p *principal) UnmarshalBinary(b []byte) error {
	if len(b) != 4*subKeySize {
		return errors.New("wrong byte slice size")
	}
	p[0] = KeyFromBytes(b[:2*subKeySize])
	p[1] = KeyFromBytes(b[2*subKeySize:])
	return nil
}

func NewPrincipal(randy io.Reader) *principal {

	/**
	 * Layout:
	 *	1st 32 bytes:	public	encrpytion key
	 *	2nd 32 bytes:	public	signing	key
	 *	3rd 32 bytes:	private encryption key
	 *	4th 32 bytes:	private signing key
	 * Therefore:
	 * principal[0][0] = public encryption
	 * principal[0][1] = public signing
	 * principal[1][0] = private encryption
	 * principal[1][1] = private signing
	 **/

	kp := NewKeyPair(randy)
	p := principal(kp)
	return &p
}

func (principal) From(b []byte) principal {

	if len(b) < 4*subKeySize {
		panic("not enough bytes")
	}
	p := new(principal)
	err := p.UnmarshalBinary(b)
	if err != nil {
		panic(err)
	}
	return *p
}
