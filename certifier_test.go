package delphi

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

var _ Certifier = (*MockCertifier)(nil)

// MockCertifier implements Certifier
type MockCertifier struct {
	privateKey *rsa.PrivateKey
}

func NewMockCertifier() *MockCertifier {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	return &MockCertifier{privateKey: privateKey}
}

func (m *MockCertifier) Public() crypto.PublicKey {
	return m.privateKey.Public()
}

func (m *MockCertifier) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return rsa.SignPKCS1v15(rand, m.privateKey, crypto.SHA256, digest)
}

func (m *MockCertifier) Verify(pub crypto.PublicKey, digest []byte, sig []byte) bool {
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return false
	}
	err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, digest, sig)
	return err == nil
}

func TestMockCertifier_SignAndVerify(t *testing.T) {
	certifier := NewMockCertifier()
	message := []byte("test message")
	hash := sha256.New()
	hash.Write(message)
	digest := hash.Sum(nil)

	signature, err := certifier.Sign(rand.Reader, digest, crypto.SHA256)
	assert.NoError(t, err)

	valid := certifier.Verify(certifier.Public(), digest, signature)
	assert.True(t, valid)
}

func TestMockCertifier_VerifyInvalidSignature(t *testing.T) {
	certifier := NewMockCertifier()
	message := []byte("test message")
	hash := sha256.New()
	hash.Write(message)
	digest := hash.Sum(nil)

	invalidSignature := []byte("invalid signature")

	valid := certifier.Verify(certifier.Public(), digest, invalidSignature)
	assert.False(t, valid)
}
func TestVerifierInterface(t *testing.T) {
	var verifier Verifier = NewMockCertifier()
	message := []byte("test message")
	hash := sha256.New()
	hash.Write(message)
	digest := hash.Sum(nil)

	// Valid signature
	signature, err := verifier.(*MockCertifier).Sign(rand.Reader, digest, crypto.SHA256)
	assert.NoError(t, err)

	valid := verifier.Verify(verifier.(*MockCertifier).Public(), digest, signature)
	assert.True(t, valid)

	// Invalid signature
	invalidSignature := []byte("invalid signature")
	valid = verifier.Verify(verifier.(*MockCertifier).Public(), digest, invalidSignature)
	assert.False(t, valid)
}

func TestCertifierInterface(t *testing.T) {
	var certifier Certifier = NewMockCertifier()
	message := []byte("test message")
	hash := sha256.New()
	hash.Write(message)
	digest := hash.Sum(nil)

	// Test Sign method
	signature, err := certifier.Sign(rand.Reader, digest, crypto.SHA256)
	assert.NoError(t, err)

	// Test Verify method
	valid := certifier.Verify(certifier.Public(), digest, signature)
	assert.True(t, valid)
}
