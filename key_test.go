package delphi

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSubKey_IsZero(t *testing.T) {
	var zeroSubKey subKey
	assert.True(t, zeroSubKey.IsZero())

	nonZeroSubKey := NewSubKey(rand.Reader)
	assert.False(t, nonZeroSubKey.IsZero())
}

func TestKey_IsZero(t *testing.T) {
	var zeroKey key
	assert.True(t, zeroKey.IsZero())

	nonZeroKey := NewKey(rand.Reader)
	assert.False(t, nonZeroKey.IsZero())
}

func TestKeyPair_IsZero(t *testing.T) {
	var zeroKeyPair keyPair
	assert.True(t, zeroKeyPair.IsZero())

	nonZeroKeyPair := NewKeyPair(rand.Reader)
	assert.False(t, nonZeroKeyPair.IsZero())
}

func TestKey_Bytes(t *testing.T) {
	k := NewKey(rand.Reader)
	expected := append(k[0][:], k[1][:]...)
	assert.Equal(t, expected, k.Bytes())
}

func TestKeyPair_Bytes(t *testing.T) {
	kp := NewKeyPair(rand.Reader)
	expected := append(kp[0].Bytes(), kp[1].Bytes()...)
	assert.Equal(t, expected, kp.Bytes())
}

func TestKeyFromBytes_Panic(t *testing.T) {
	assert.Panics(t, func() {
		KeyFromBytes([]byte{1, 2, 3})
	})
}
