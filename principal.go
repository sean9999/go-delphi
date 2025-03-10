package delphi

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"

	"github.com/sean9999/pear"
)

const ByteSize = 128

var ErrBadKey = errors.New("bad key")

type CryptOpts struct {
	Nonce []byte
	AAED  []byte
}

// a Principal contains cryptographic key material
// and can sign, verify, encrypt, and decrypt [Message]s.
type Principal = KeyPair

// Sign() signs a digest
func (p *Principal) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	sig := ed25519.Sign(p.privateSigningKey(), digest)
	return sig, nil
}

// Verify() verifies a signature
func (p *Principal) Verify(delphiPubKey crypto.PublicKey, digest []byte, sig []byte) bool {
	edpub := ed25519.PublicKey(delphiPubKey.(Key).Signing().Bytes())
	return ed25519.Verify(edpub, digest, sig)
}

// Encrypt() encrypts a [Message]
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

	binHeaders, err := msg.Headers.MarshalBinary()
	if err != nil {
		return err
	}

	ciph, err := encrypt(sec, msg.PlainText, msg.nonce.Bytes(), binHeaders)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrDelphi, err)
	}

	msg.cipherText = ciph
	msg.PlainText = nil

	return nil
}

// Decrypt() decrypts a [Message]
func (p *Principal) Decrypt(msg *Message, opts crypto.DecrypterOpts) error {

	sharedSec, err := extractSharedSecret(msg.ephPubkey, p.privateEncryptionKey().Bytes(), p.publicEncryptionKey().Bytes())
	if err != nil {
		return fmt.Errorf("could not decrypt: %w", err)
	}

	binHeaders, err := msg.Headers.MarshalBinary()
	if err != nil {
		return err
	}

	plainTxt, err := decrypt(sharedSec, msg.cipherText, msg.nonce[:], binHeaders)
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
		return pear.Errorf("wrong byte slice size. wanted %d but got %d", 4*subKeySize, len(b))
	}
	p[0] = KeyFromBytes(b[:2*subKeySize])
	p[1] = KeyFromBytes(b[2*subKeySize:])
	return nil
}

// NewPrincipal() creates a new [Principal]
func NewPrincipal(randy io.Reader) *Principal {
	kp := NewKeyPair(randy)
	p := Principal(kp)
	return &p
}

// From() re-hydrates a [Principal] from a byte slice
func (Principal) From(b []byte) (Principal, error) {
	if len(b) < 4*subKeySize {
		return Principal{}, fmt.Errorf("%w: not enough bytes. Expected %d but got %d", ErrBadKey, 4*subKeySize, len(b))
	}
	p := new(Principal)
	err := p.UnmarshalBinary(b)
	if err != nil {
		return Principal{}, err
	}
	return *p, nil
}
