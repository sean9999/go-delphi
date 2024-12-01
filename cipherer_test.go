package delphi

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

type MockCipherer struct{}

func (m *MockCipherer) Encrypt(r io.Reader, msg *Message, opts EncrypterOpts) error {
	// Mock encryption logic
	msg.cipherText = []byte("encrypted")
	return nil
}

func (m *MockCipherer) Decrypt(msg *Message, priv ed25519.PrivateKey, opts crypto.DecrypterOpts) error {
	// Mock decryption logic
	msg.PlainText = []byte("decrypted")
	return nil
}

func (m *MockCipherer) Public() crypto.PublicKey {
	return ed25519.PublicKey{}
}

func TestCipherer_Encrypt(t *testing.T) {
	cipherer := &MockCipherer{}
	msg := NewMessage(rand.Reader, []byte("hello world"))

	err := cipherer.Encrypt(rand.Reader, msg, nil)
	assert.NoError(t, err)
	assert.Equal(t, []byte("encrypted"), msg.cipherText)
}

func TestCipherer_Decrypt(t *testing.T) {
	cipherer := &MockCipherer{}
	msg := NewMessage(rand.Reader, []byte("hello world"))
	msg.cipherText = []byte("encrypted")

	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	err := cipherer.Decrypt(msg, priv, nil)
	assert.NoError(t, err)
	assert.Equal(t, []byte("decrypted"), msg.PlainText)
}
