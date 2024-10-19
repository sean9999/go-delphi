package msg

import (
	"crypto/ecdh"
	"errors"
	"fmt"
	"io"

	"github.com/vmihailenco/msgpack/v5"
	"golang.org/x/crypto/chacha20poly1305"
)

const NonceSize = chacha20poly1305.NonceSize

var ErrNotImplemented = errors.New("not implemented")

type Envelope struct {
	To                 *ecdh.PublicKey
	From               *ecdh.PublicKey
	EphemeralPublicKey []byte
	Nonce              []byte
	Message            Message
	Signature          []byte
}

func (m Message) MarhsalBinary() ([]byte, error) {
	return msgpack.Marshal(m)
}

func (m *Message) UnmarshalBinary(p []byte) error {
	return msgpack.Unmarshal(p, m)
}

// type Encrypter interface {
// 	Read(p []byte) (int, error)
// 	Write(p []byte) (int, error)
// }

func (e *Envelope) Encrypt(randomness io.Reader) error {
	sharedSec, ephemeralPublicKey, err := generateSharedSecret(e.To, randomness)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrEncryptionFailed, err)
	}
	ciphTxt, err := encrypt(sharedSec, e.Message.PlainText)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrEncryptionFailed, err)
	}
	e.EphemeralPublicKey = ephemeralPublicKey
	e.Message.CipherText = ciphTxt
	e.Message.PlainText = nil
	return nil
}

func (e *Envelope) Decrypt(recipientPrivKey *ecdh.PrivateKey) error {
	sharedSec, err := extractSharedSecret(e.EphemeralPublicKey, recipientPrivKey.Bytes(), e.To.Bytes())
	if err != nil {
		return fmt.Errorf("%w: %w", ErrDecryptionFailed, err)
	}
	plain, err := decrypt(sharedSec, e.Message.CipherText)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrDecryptionFailed, err)
	}
	e.Message.PlainText = plain
	e.Message.CipherText = nil
	return nil
}
