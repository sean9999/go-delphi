package delphi

import (
	"crypto/ecdh"
	"errors"
	"fmt"
	"io"

	"github.com/google/uuid"
	stablemap "github.com/sean9999/go-stable-map"
	"github.com/vmihailenco/msgpack/v5"
	"golang.org/x/crypto/chacha20poly1305"
)

const NonceSize = chacha20poly1305.NonceSize

var ErrNotImplemented = errors.New("not implemented")

type Message struct {
	To                 *ecdh.PublicKey
	From               *ecdh.PublicKey
	Metadata           *stablemap.StableMap[string, any] // additional authenticated data (AAD)
	EphemeralPublicKey []byte
	Nonce              []byte
	CipherText         []byte
	PlainText          []byte
	Signature          []byte
}

func (m *Message) ensureNonce() []byte {
	if m.Nonce == nil {
		n := uuid.New()
		b, _ := n.MarshalBinary()
		m.Nonce = b
	}
	return m.Nonce
}

func (m *Message) MarhsalBinary() ([]byte, error) {
	return msgpack.Marshal(m)
}

func (m *Message) UnmarshalBinary(p []byte) error {
	return msgpack.Unmarshal(p, m)
}

// type Encrypter interface {
// 	Read(p []byte) (int, error)
// 	Write(p []byte) (int, error)
// }

func (msg *Message) Encrypt(randomness io.Reader) error {
	sharedSec, ephemeralPublicKey, err := generateSharedSecret(msg.To.Bytes(), randomness)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrEncryptionFailed, err)
	}
	msg.ensureNonce()
	ciphTxt, err := encrypt(sharedSec, msg.PlainText, msg.Nonce, msg.Metadata)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrEncryptionFailed, err)
	}
	msg.EphemeralPublicKey = ephemeralPublicKey
	msg.CipherText = ciphTxt
	msg.PlainText = nil
	return nil
}

func (msg *Message) Decrypt(recipientPrivKey *ecdh.PrivateKey) error {
	sharedSec, err := extractSharedSecret(msg.EphemeralPublicKey, recipientPrivKey.Bytes(), msg.To.Bytes())
	if err != nil {
		return fmt.Errorf("%w: %w", ErrDecryptionFailed, err)
	}
	plain, err := decrypt(sharedSec, msg.CipherText, msg.Nonce, msg.Metadata)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrDecryptionFailed, err)
	}
	msg.PlainText = plain
	msg.CipherText = nil
	return nil
}

func NewMessage(plainTxt []byte) *Message {

	msg := new(Message)

	msg.Metadata = stablemap.New[string, any]()

	nonce := uuid.New()
	b, err := nonce.MarshalBinary()
	if err != nil {
		panic(err)
	}

	msg.PlainText = plainTxt

	msg.Nonce = b

	return msg

}
