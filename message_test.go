package delphi

import (
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
)

var randy = rand.Reader

func TestEncrypt(t *testing.T) {

	sentence := []byte("hello world")

	alice := NewPrincipal(randy)
	bob := NewPrincipal(randy)
	msg := NewMessage(randy, sentence)
	msg.from = alice.PublicKey()
	msg.to = bob.PublicKey()

	msg.headers.Set("foo", []byte("bar"))
	msg.headers.Set("bing", []byte("bat"))

	err := msg.Encrypt(randy, alice, nil)
	assert.NoError(t, err)

	plain, err := bob.Decrypt(nil, msg, nil)
	assert.NoError(t, err)

	assert.Equal(t, sentence, plain)

}

func TestEncrypt_No_Recipient(t *testing.T) {

	sentence := []byte("hello world")

	alice := NewPrincipal(randy)
	//bob := NewPrincipal(randy)
	msg := NewMessage(randy, sentence)
	msg.from = alice[0]
	//msg.to = bob[0]

	err := msg.Encrypt(randy, alice, nil)
	assert.ErrorIs(t, err, ErrDelphi)
	assert.ErrorIs(t, err, ErrBadKey)

}

func TestSign(t *testing.T) {

	alice := NewPrincipal(randy)
	bob := NewPrincipal(randy)
	msg := NewMessage(randy, []byte("hello world"))
	msg.from = alice[0]
	msg.Sign(randy, alice)
	digest, err := msg.Digest(sha256.New())
	assert.NoError(t, err)
	cool := bob.Verify(msg.from, digest, msg.signature)
	assert.True(t, cool)

}
