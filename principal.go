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
var _ IPrincipal = (*Principal)(nil)

// a IPrincipal is a holder of a public/private key-pair
// that can perform encryption, decryption, signing, and verifying operations.
type IPrincipal interface {
	Cipherer
	Certifier
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
	PublicKey() Key
	PrivateKey() Key
}

/**
 * Layout:
 *	1st 32 bytes:	public	encrpytion key
 *	2nd 32 bytes:	public	signing	key
 *	3rd 32 bytes:	private encryption key
 *	4th 32 bytes:	private signing key
 **/
type Principal = KeyPair

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

func (p *Principal) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	sig := ed25519.Sign(p.privateSigningKey(), digest)
	return sig, nil
}

func (p *Principal) Verify(delphiPubKey crypto.PublicKey, digest []byte, sig []byte) bool {
	dpub := delphiPubKey.(Key)
	edpub := ed25519.PublicKey(dpub[1][:])
	return ed25519.Verify(edpub, digest, sig)
}

var ErrBadKey = errors.New("bad key")

func (p *Principal) Encrypt(randy io.Reader, msg *Message, opts any) error {

	if msg.Encrypted() {
		return fmt.Errorf("%w: already encrypted", ErrDelphi)
	}
	if !msg.Plain() {
		return fmt.Errorf("%w: there is no plain text to encrypt", ErrDelphi)
	}

	if msg.Recipient.IsZero() {
		return fmt.Errorf("%w: recipient: %w", ErrDelphi, ErrBadKey)
	}

	sec, eph, err := generateSharedSecret(msg.Recipient.Encryption().Bytes(), randy)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrDelphi, err)
	}

	msg.ensureNonce(randy)
	msg.ephPubkey = eph

	ciph, err := encrypt(sec, msg.PlainText, msg.nonce.Bytes(), msg.Headers)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrDelphi, err)
	}

	msg.cipherText = ciph
	msg.PlainText = nil

	// sec, err := extractSharedSecret(msg.EphemeralKey(), p.privateEncryptionKey().Bytes(), msg.Recipient().Bytes())
	// if err != nil {
	// 	return err
	// }

	return nil
}

func (p *Principal) Decrypt(msg *Message, opts crypto.DecrypterOpts) error {

	sharedSec, err := extractSharedSecret(msg.ephPubkey, p.privateEncryptionKey().Bytes(), p.publicEncryptionKey().Bytes())
	if err != nil {
		return fmt.Errorf("could not decrypt: %w", err)
	}
	plainTxt, err := decrypt(sharedSec, msg.cipherText, msg.nonce[:], msg.Headers)
	if err != nil {
		return fmt.Errorf("could not decrypt: %w", err)
	}
	msg.PlainText = plainTxt
	msg.cipherText = nil
	return nil
}

// func (p principal) byteRange(from, to int) []byte {
// 	return p[from:to]
// }

func (p *Principal) publicSigningKey() ed25519.PublicKey {
	return ed25519.PublicKey(p[0][1][:])
}

func (p *Principal) privateSigningKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(p[1][1][:])
}

func (p *Principal) privateEncryptionKey() *ecdh.PrivateKey {
	priv, err := ecdh.X25519().NewPrivateKey(p[1][0][:])
	if err != nil {
		panic(err)
	}
	return priv
}

func (p *Principal) publicEncryptionKey() *ecdh.PublicKey {
	return p.privateEncryptionKey().PublicKey()
}

func (p *Principal) PublicKey() Key {
	return p[0]
}

func (p *Principal) PrivateKey() Key {
	return p[1]
}

func (p *Principal) Public() crypto.PublicKey {
	//	i guess the signing key is most appropriate here?
	return p[0]
}

func (p *Principal) Equal(p2 crypto.PublicKey) bool {
	//	true if key matches either encryption or signing key
	return p.publicSigningKey().Equal(p2) || p.publicEncryptionKey().Equal(p2)
}

func (p *Principal) MarshalBinary() ([]byte, error) {
	return p.Bytes(), nil
}

func (p *Principal) UnmarshalBinary(b []byte) error {
	if len(b) != 4*subKeySize {
		return errors.New("wrong byte slice size")
	}
	p[0] = KeyFromBytes(b[:2*subKeySize])
	p[1] = KeyFromBytes(b[2*subKeySize:])
	return nil
}

func NewPrincipal(randy io.Reader) *Principal {

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
	p := Principal(kp)
	return &p
}

func (Principal) From(b []byte) Principal {

	if len(b) < 4*subKeySize {
		panic("not enough bytes")
	}
	p := new(Principal)
	err := p.UnmarshalBinary(b)
	if err != nil {
		panic(err)
	}
	return *p
}
