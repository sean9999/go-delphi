package delphi

import (
	"crypto"
	"crypto/ecdh"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	stablemap "github.com/sean9999/go-stable-map"
	"github.com/vmihailenco/msgpack/v5"
)

var ErrNotImplemented = errors.New("not implemented")

type Message struct {
	To                 key
	From               key
	Metadata           *stablemap.StableMap[string, any] // additional authenticated data (AAD)
	EphemeralPublicKey []byte
	Nonce              Nonce
	CipherText         []byte
	PlainText          []byte
	Signature          []byte
}

func (m *Message) ensureNonce(randy io.Reader) Nonce {

	if !m.Nonce.IsZero() {
		return m.Nonce
	}

	nonce := Nonce{}
	i, err := randy.Read(nonce[:])

	if i != NonceSize {
		panic("wrong length")
	}
	if err != nil {
		panic("error reading from randy into nonce")
	}

	m.Nonce = nonce

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
	msg.ensureNonce(randomness)
	ciphTxt, err := encrypt(sharedSec, msg.PlainText, msg.Nonce[:], msg.Metadata)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrEncryptionFailed, err)
	}
	msg.EphemeralPublicKey = ephemeralPublicKey
	msg.CipherText = ciphTxt
	msg.PlainText = nil
	return nil
}

func (msg *Message) IsPlain() bool {
	return len(msg.PlainText) > 0
}

func (msg *Message) IsEncrypted() bool {
	return len(msg.CipherText) > 0
}

func (msg *Message) IsValid() bool {
	return (msg.IsPlain() && !msg.IsEncrypted()) || (msg.IsEncrypted() && !msg.IsPlain())
}

func (msg *Message) Digest() ([]byte, error) {

	//	Some fields are included. Some are required. Some are intentially omitted:
	//	To is omitted. A messages digest is the same regardless of who it's sent to.
	//	From is required. Who its from is integral.
	//	Metadata is included if it exists, but not if not. It's treated as AAD.
	//	Nonce is required, to ensure uniqueness
	//	Ephemeral Key is omitted. Nonce provides all necessary randomness
	//	Either plain or cipher text is included. It's an error to have both or neither.

	if !msg.IsValid() {
		return nil, errors.New("message is not valid")
	}
	if msg.Nonce.IsZero() {
		return nil, errors.New("nonce is zero")
	}
	if msg.From.IsZero() {
		return nil, errors.New("From is zero")
	}

	sum := make([]byte, 0)
	sum = append(sum, msg.From.Bytes()...)
	// headers, err := msg.Metadata.MarshalBinary()
	// if err != nil {
	// 	return nil, err
	// }
	// sum = append(sum, headers...)

	sum = append(sum, msg.Nonce[:]...)

	if msg.IsEncrypted() {
		sum = append(sum, msg.CipherText...)
	} else {
		sum = append(sum, msg.PlainText...)
	}

	dig := sha256.New()
	return dig.Sum(sum), nil
}

func (msg *Message) Sign(randy io.Reader, signer crypto.Signer) error {
	var errSign = errors.New("could not sign message")
	digest, err := msg.Digest()
	if err != nil {
		return fmt.Errorf("%w: %w", errSign, err)
	}
	sig, err := signer.Sign(randy, digest, nil)
	if err != nil {
		return fmt.Errorf("%w: %w", errSign, err)
	}
	msg.Signature = sig
	return nil
}

// func (msg *Message) Sign(randomness io.Reader, signer crypto.Signer) error {
// 	signer.Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts)
// }

func (msg *Message) Decrypt(recipientPrivKey *ecdh.PrivateKey) error {
	sharedSec, err := extractSharedSecret(msg.EphemeralPublicKey, recipientPrivKey.Bytes(), msg.To.Bytes())
	if err != nil {
		return fmt.Errorf("%w: %w", ErrDecryptionFailed, err)
	}
	plain, err := decrypt(sharedSec, msg.CipherText, msg.Nonce[:], msg.Metadata)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrDecryptionFailed, err)
	}
	msg.PlainText = plain
	msg.CipherText = nil
	return nil
}

func NewMessage(randy io.Reader, plainTxt []byte) *Message {

	msg := new(Message)
	msg.Metadata = stablemap.New[string, any]()
	msg.ensureNonce(randy)
	msg.PlainText = plainTxt

	return msg

}
