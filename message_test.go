package delphi

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

var randy = rand.Reader

func TestEncrypt(t *testing.T) {

	sentence := []byte("hello world")

	alice := NewPrincipal(randy)
	bob := NewPrincipal(randy)
	msg := NewMessage(randy, "DELPHI PLAIN MESSAGE", sentence)
	msg.SenderKey = alice.PublicKey()
	msg.RecipientKey = bob.PublicKey()

	msg.Headers["foo"] = "bar"
	msg.Headers["bing"] = "bat"

	err := msg.Encrypt(randy, alice, nil)
	assert.NoError(t, err)
	err = bob.Decrypt(msg, nil)
	assert.NoError(t, err)
	assert.Equal(t, sentence, msg.PlainText)

}

func TestEncrypt_No_Recipient(t *testing.T) {

	sentence := []byte("hello world")
	alice := NewPrincipal(randy)
	//bob := NewPrincipal(randy)
	msg := NewMessage(randy, PlainMessage, sentence)
	msg.SenderKey = alice[0]
	//msg.to = bob[0]

	err := msg.Encrypt(randy, alice, nil)
	assert.ErrorIs(t, err, ErrDelphi)
	assert.ErrorIs(t, err, ErrBadKey)

}

func TestSign(t *testing.T) {

	alice := NewPrincipal(randy)
	bob := NewPrincipal(randy)
	msg := NewMessage(randy, PlainMessage, []byte("hello world"))
	msg.SenderKey = alice[0]
	msg.Sign(randy, alice)
	digest, err := msg.Digest()
	assert.NoError(t, err)
	cool := bob.Verify(msg.SenderKey, digest, msg.Sig)
	assert.True(t, cool)

}
