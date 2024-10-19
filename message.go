package delphi

import (
	"crypto/ecdh"
	"io"
)

type Message struct {
	AAD        []byte
	Headers    map[string]string
	CipherText []byte
	PlainText  []byte
}

// a valid Message may only have CipherText or PlainText.
// Not neither, and not both.
func (m Message) Valid() bool {
	return (m.Encypted() && !m.Plain()) || (m.Plain() && !m.Encypted())
}

func (m Message) Encypted() bool {
	return m.CipherText != nil && m.PlainText == nil
}

func (m Message) Plain() bool {
	return m.CipherText == nil && m.PlainText != nil
}

func (m Message) Sign(randomness io.Reader, me *ecdh.PrivateKey) (sig []byte, nonce []byte, err error) {
	return nil, nil, ErrNotImplemented
}
