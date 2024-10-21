package delphi

import (
	"crypto/rand"
	"testing"
)

func TestEncrypt(t *testing.T) {

	randy := rand.Reader

	alice := NewPrincipal(randy)
	bob := NewPrincipal(randy)

	msg := NewMessage(randy, []byte("hello world"))

	msg.From = alice.publicEncryptionKey()
	msg.To = bob.publicEncryptionKey()

	msg.Encrypt(rand.Reader)

}
