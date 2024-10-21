package delphi

import (
	"crypto/rand"
	"testing"
)

func TestEncrypt(t *testing.T) {

	alice := NewPrincipal(rand.Reader)
	bob := NewPrincipal(rand.Reader)

	msg := NewMessage([]byte("hello world"))

	msg.From = alice.publicEncryptionKey()
	msg.To = bob.publicEncryptionKey()

	msg.Encrypt(rand.Reader)

}
