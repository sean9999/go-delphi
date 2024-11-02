package delphi

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNonce_IsZero(t *testing.T) {
	// Test when nonce is zero
	var zeroNonce Nonce
	assert.True(t, zeroNonce.IsZero(), "Expected zeroNonce to be zero")

	// Test when nonce is not zero
	var nonZeroNonce Nonce
	nonZeroNonce[0] = 1
	assert.False(t, nonZeroNonce.IsZero(), "Expected nonZeroNonce to be non-zero")
}
