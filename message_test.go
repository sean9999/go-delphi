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
	msg := ComposeMessage(randy, "DELPHI PLAIN MESSAGE", sentence)
	msg.SenderKey = alice.PublicKey()

	msg.Headers["foo"] = "bar"
	msg.Headers["bing"] = "bat"

	err := msg.Encrypt(randy, alice, bob.PublicKey(), nil)
	assert.NoError(t, err)
	err = bob.Decrypt(msg, nil)
	assert.NoError(t, err)
	assert.Equal(t, sentence, msg.PlainText)

}

func TestPEMIdempotent(t *testing.T) {

	sentence := []byte("hello world")

	t.Run("plain message", func(t *testing.T) {

		//	msg 1
		msg1 := ComposeMessage(randy, "DELPHI PLAIN MESSAGE", sentence)
		msg1.Headers["foo"] = "bar"
		msg1.Headers["bing"] = "bat"

		//	pem 1
		p1 := msg1.ToPEM()

		//	msg 2
		msg2 := new(Message)
		err := msg2.FromPEM(p1)
		assert.NoError(t, err)

		//	pem 2
		p2 := msg2.ToPEM()
		assert.Equal(t, p2.Type, p1.Type)
		assert.ElementsMatch(t, p1.Bytes, p2.Bytes)
		assert.Equal(t, p1.Headers, p2.Headers)

	})

	t.Run("encrypted message", func(t *testing.T) {

		randy := rand.Reader
		me := NewPrincipal(randy)
		them := NewPrincipal(randy)

		msg := me.ComposeMessage(randy, sentence)
		msg.Encrypt(randy, me, them.PublicKey(), nil)
		assert.Equal(t, EncryptedMessage, msg.Subject)

		p1 := msg.ToPEM()
		msg2 := new(Message)
		msg2.FromPEM(p1)
		p2 := msg2.ToPEM()

		assert.Equal(t, msg.Nonce, msg2.Nonce)
		assert.Equal(t, msg.RecipientKey, msg2.RecipientKey)
		assert.Equal(t, msg.CipherText, msg2.CipherText)
		assert.Equal(t, p1.Bytes, p2.Bytes)
		assert.Equal(t, p1.Headers, p2.Headers)

	})

}

func TestEncrypt_No_Recipient(t *testing.T) {

	sentence := []byte("hello world")
	alice := NewPrincipal(randy)
	msg := ComposeMessage(randy, PlainMessage, sentence)
	msg.SenderKey = alice[0]
	noRecipient := NewKey(nil)
	err := msg.Encrypt(randy, alice, noRecipient, nil)
	assert.ErrorIs(t, err, ErrDelphi)
	assert.ErrorIs(t, err, ErrBadKey)

}

func TestSign(t *testing.T) {

	alice := NewPrincipal(randy)
	bob := NewPrincipal(randy)
	msg := ComposeMessage(randy, PlainMessage, []byte("hello world"))
	msg.SenderKey = alice[0]
	msg.Sign(randy, alice)
	digest, err := msg.Digest()
	assert.NoError(t, err)
	cool := bob.Verify(msg.SenderKey, digest, msg.Sig)
	assert.True(t, cool)

}
