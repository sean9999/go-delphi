package delphi

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

var randy = rand.Reader

func TestNewPrincipal(t *testing.T) {

	ed := ecdh.X25519()
	priv, err := ed.GenerateKey(randy)
	assert.NoError(t, err)
	assert.Len(t, priv.Bytes(), 32)
	assert.Len(t, priv.PublicKey().Bytes(), 32)

	pub, privPub, err := ed25519.GenerateKey(randy)
	assert.NoError(t, err)
	assert.Len(t, privPub, 64)
	assert.Len(t, pub, 32)

	assert.EqualValues(t, pub, privPub[32:])

}
