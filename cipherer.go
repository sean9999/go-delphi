package delphi

import (
	"crypto"
)

type Encrypter interface {
	Encrypt(msg []byte, recipient crypto.PublicKey, opts any) ([]byte, error)
}

// a Cipherer can encrypt and decrypt an [Envelope]
type Cipherer interface {
	crypto.PrivateKey
	Encrypter
	crypto.Decrypter
}

// type cipherer [64]byte

// func (c cipherer) keys() (*ecdh.PrivateKey, *ecdh.PublicKey) {

// 	curry := ecdh.X25519()

// 	//	private key is all 64 bytes, because pubkey is part of privatekey (last 32 bytes)
// 	priv, err := curry.NewPrivateKey(c[:])
// 	if err != nil {
// 		panic(err)
// 	}
// 	pub := priv.PublicKey()
// 	return priv, pub
// }

// func (c cipherer) Encrypt(msg *Message, randy io.Reader, opts any) error {
// 	//priv, pub := c.keys()
// 	sec, ephKey, err := generateSharedSecret(msg.To.Bytes(), randy)
// 	if err != nil {
// 		return err
// 	}
// 	msg.EphemeralPublicKey = ephKey
// 	nonce := uuid.New()
// 	msg.nonce = nonce[:]
// 	crypt, err := encrypt(sec, msg.PlainText, nonce[:], msg.Metadata)
// 	if err != nil {
// 		return err
// 	}
// 	msg.CipherText = crypt
// 	msg.PlainText = nil
// 	return nil
// }

// func encrypt(key, plaintext, nonce, aad []byte) ([]byte, error) {
// 	aead, err := chacha20poly1305.New(key)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return aead.Seal(nil, nonce, plaintext, aad), nil
// }

// func (e *Message) Encrypt(randomness io.Reader) error {
// 	sharedSec, ephemeralPublicKey, err := generateSharedSecret(e.To, randomness)
// 	if err != nil {
// 		return fmt.Errorf("%w: %w", ErrEncryptionFailed, err)
// 	}
// 	ciphTxt, err := encrypt(sharedSec, e.PlainText)
// 	if err != nil {
// 		return fmt.Errorf("%w: %w", ErrEncryptionFailed, err)
// 	}
// 	e.EphemeralPublicKey = ephemeralPublicKey
// 	e.CipherText = ciphTxt
// 	e.PlainText = nil
// 	return nil
// }
