package delphi

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

var randy = rand.Reader

func TestEncrypt(t *testing.T) {

	alice := NewPrincipal(randy)
	bob := NewPrincipal(randy)

	msg := NewMessage(randy, []byte("hello world"))

	msg.From = alice[0]
	msg.To = bob[0]

	msg.Encrypt(rand.Reader)

}

func TestSign(t *testing.T) {

	alice := NewPrincipal(randy)
	bob := NewPrincipal(randy)

	msg := NewMessage(randy, []byte("hello world"))

	msg.From = alice[0]
	msg.Sign(randy, alice)

	digest, err := msg.Digest()
	assert.NoError(t, err)

	cool := bob.Verify(msg.From, digest, msg.Signature)
	assert.True(t, cool)

}
