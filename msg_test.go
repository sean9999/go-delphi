package delphi

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncrypt(t *testing.T) {

	alice := NewPrincipal(rand.Reader)
	bob := NewPrincipal(rand.Reader)

	msg := Message{
		PlainText: []byte("hello world."),
	}

	env := &Envelope{
		To:      bob.pub,
		From:    alice.pub,
		Message: msg,
	}

	err := env.Encrypt(rand.Reader)
	assert.NoError(t, err)

	err = env.Decrypt(bob.priv)
	assert.NoError(t, err)

	assert.Equal(t, []byte("hello world."), env.Message.PlainText, "decryption bad")

}
