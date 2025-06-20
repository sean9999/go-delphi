package delphi

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"

	"encoding/pem"

	"github.com/goombaio/namegenerator"
	"github.com/sean9999/pear"
)

var ErrBadKey = errors.New("bad key")

type CryptOpts struct {
	Nonce []byte
	AAD   []byte
}

// A Principal contains cryptographic key material
// and can sign, verify, encrypt, and decrypt [Message]s.
type Principal = KeyPair

// Sign signs a digest
func (p Principal) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	sig := ed25519.Sign(p.privateSigningKey(), digest)
	return sig, nil
}

// Assert creates a signed assertion
func (p Principal) Assert(randy io.Reader) (*Message, error) {

	body := []byte("I assert that I am me.")
	msg := p.ComposeMessage(randy, body)
	msg.Subject = Assertion

	err := msg.Sign(randy, p)
	if err != nil {
		return nil, fmt.Errorf("could not create assertion: %w", err)
	}

	return msg, nil

}

// Verify verifies a signature
func (p Principal) Verify(delphiPubKey crypto.PublicKey, digest []byte, sig []byte) bool {
	pubKey := ed25519.PublicKey(delphiPubKey.(Key).Signing().Bytes())
	return ed25519.Verify(pubKey, digest, sig)
}

// Encrypt encrypts a [Message]
func (p Principal) Encrypt(randy io.Reader, msg *Message, recipient Key, _ any) error {

	if msg.Encrypted() {
		return fmt.Errorf("%w: already encrypted", ErrDelphi)
	}
	if !msg.Plain() {
		return fmt.Errorf("%w: there is no plain text to encrypt", ErrDelphi)
	}
	if recipient.IsZero() {
		return ErrBadKey
	}

	msg.SenderKey = p.PublicKey()
	msg.RecipientKey = recipient
	if msg.RecipientKey.IsZero() {
		return fmt.Errorf("%w: recipient: %w", ErrDelphi, ErrBadKey)
	}

	sec, eph, err := generateSharedSecret(msg.RecipientKey.Encryption().Bytes(), randy)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrDelphi, err)
	}

	msg.ensureNonce(randy)
	msg.Eph = eph

	aad, err := msg.Headers.MarshalBinary()
	if err != nil {
		return err
	}

	cipherText, err := encrypt(sec, msg.PlainText, msg.Nonce.Bytes(), aad)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrDelphi, err)
	}

	msg.CipherText = cipherText
	msg.PlainText = nil

	if msg.Subject == PlainMessage {
		msg.Subject = EncryptedMessage
	}

	return nil
}

// Decrypt decrypts a [Message]
func (p Principal) Decrypt(msg *Message, _ crypto.DecrypterOpts) error {

	sharedSec, err := extractSharedSecret(msg.Eph, p.privateEncryptionKey().Bytes(), p.publicEncryptionKey().Bytes())
	if err != nil {
		return fmt.Errorf("could not decrypt: %w", err)
	}

	aad, err := msg.Headers.MarshalBinary()
	if err != nil {
		return fmt.Errorf("could not decrypt: %w", err)
	}

	plainTxt, err := decrypt(sharedSec, msg.CipherText, msg.Nonce.Bytes(), aad)
	if err != nil {
		return fmt.Errorf("could not decrypt: %w", err)
	}
	msg.Subject = PlainMessage
	msg.PlainText = plainTxt
	msg.CipherText = nil
	return nil
}

func (p Principal) publicSigningKey() ed25519.PublicKey {
	return ed25519.PublicKey(p[0][1][:])
}

func (p Principal) privateSigningKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(p[1][1][:])
}

func (p Principal) privateEncryptionKey() *ecdh.PrivateKey {
	priv, err := ecdh.X25519().NewPrivateKey(p[1][0][:])
	if err != nil {
		panic(err)
	}
	return priv
}

func (p Principal) publicEncryptionKey() *ecdh.PublicKey {
	return p.privateEncryptionKey().PublicKey()
}

func (p Principal) PublicKey() Key {
	return p[0]
}

func (p Principal) PrivateKey() Key {
	return p[1]
}

func (p Principal) Public() crypto.PublicKey {
	return p[0]
}

func (p Principal) Equal(p2 crypto.PublicKey) bool {
	//	true if key matches either encryption or signing key
	return p.publicSigningKey().Equal(p2) || p.publicEncryptionKey().Equal(p2)
}

func (p Principal) MarshalBinary() ([]byte, error) {
	return p.Bytes(), nil
}

func (p *Principal) UnmarshalBinary(b []byte) error {

	if len(b) != 4*SubKeySize {
		return pear.Errorf("wrong byte slice size. wanted %d but got %d", 4*SubKeySize, len(b))
	}
	p[0] = KeyFromBytes(b[:2*SubKeySize])
	p[1] = KeyFromBytes(b[2*SubKeySize:])
	return nil
}

// NewPrincipal creates a new [Principal]
func NewPrincipal(randy io.Reader) Principal {
	kp := NewKeyPair(randy)
	p := Principal(kp)
	return p
}

// From re-hydrates a [Principal] from a byte slice
func (Principal) From(b []byte) (Principal, error) {
	if len(b) < 4*SubKeySize {
		return Principal{}, fmt.Errorf("%w: not enough bytes. Expected %d but got %d", ErrBadKey, 4*SubKeySize, len(b))
	}
	p := new(Principal)
	err := p.UnmarshalBinary(b)
	if err != nil {
		return Principal{}, err
	}
	return *p, nil
}

// A Nickname is a very memorable string for humans only. It has weak uniqueness that is good enough for some uses.
func (p Principal) Nickname() string {
	return p.PublicKey().Nickname()
}

// A Peer is the public portion of a Principal, which is a public-private key pair.
type Peer = Key

// A Nickname is a very memorable string for humans only. It has weak uniqueness that is good enough for some uses.
func (p Peer) Nickname() string {
	seed := p.ToInt64()
	nameGenerator := namegenerator.NewNameGenerator(seed)
	name := nameGenerator.Generate()
	return name
}

func (p Peer) MarshalPEM() (pem.Block, error) {
	blk := pem.Block{
		Type: string(Pubkey),
		Headers: map[string]string{
			fmt.Sprintf("%s/%s", Keyspace, "nick"):    p.Nickname(),
			fmt.Sprintf("%s/%s", Keyspace, "version"): Version,
		},
		Bytes: p.Bytes(),
	}
	return blk, nil
}

func (p Principal) MarshalPEM() (pem.Block, error) {
	blk := pem.Block{
		Type: string(Privkey),
		Headers: map[string]string{
			fmt.Sprintf("%s/%s", Keyspace, "nick"):    p.Nickname(),
			fmt.Sprintf("%s/%s", Keyspace, "version"): Version,
		},
		Bytes: p.Bytes(),
	}
	return blk, nil
}

func (p *Principal) UnmarshalPEM(b pem.Block) error {
	if b.Type != "DELPHI PRIVATE KEY" {
		return errors.New("wrong type of PEM")
	}
	if len(b.Bytes) != SubKeySize*4 {
		return fmt.Errorf("wrong byte size for private key. wanted %d but got %d", SubKeySize*4, len(b.Bytes))
	}
	copy(p[0][0][:], b.Bytes[0:SubKeySize])
	copy(p[0][1][:], b.Bytes[SubKeySize:SubKeySize*2])
	copy(p[1][0][:], b.Bytes[SubKeySize*2:SubKeySize*3])
	copy(p[1][1][:], b.Bytes[SubKeySize*3:])
	return nil
}

func (p Principal) ComposeMessage(randy io.Reader, body []byte) *Message {
	msg := ComposeMessage(randy, "DELPHI PLAIN MESSAGE", body)
	msg.SenderKey = p.PublicKey()
	msg.PlainText = body
	return msg
}
