package delphi_test

import (
	"crypto/rand"
	"testing"

	"github.com/sean9999/go-delphi"
	"github.com/stretchr/testify/assert"
)

func TestExample(t *testing.T) {

	//	some plain text
	sentence := []byte("hello world")

	//	create two principals
	alice := delphi.NewPrincipal(rand.Reader)
	bob := delphi.NewPrincipal(rand.Reader)

	//	create a message for bob, from alice
	msg := delphi.NewMessage(rand.Reader, sentence)
	msg.Sender = alice.PublicKey()
	msg.Recipient = bob.PublicKey()

	//	add some metadata (this becomes AAD)
	msg.Headers.Set("foo", []byte("bar"))
	msg.Headers.Set("bing", []byte("bat"))

	//	encrypt message
	err := msg.Encrypt(rand.Reader, alice, nil)
	assert.NoError(t, err)

	//	decrpyt message
	err = bob.Decrypt(msg, nil)
	assert.NoError(t, err)

	//	is decrypted text same as plain text?
	assert.Equal(t, sentence, msg.PlainText)

	//	has the metadata survived?
	foo, ok := msg.Headers.Get("foo")
	assert.True(t, ok)
	assert.Equal(t, []byte("bar"), foo)

}