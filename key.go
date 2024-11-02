package delphi

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"io"
)

const subKeySize = 32

// a subkey is either: a public encryption, public signing, private encryption, or private signing key
type subKey [subKeySize]byte

func (s subKey) IsZero() bool {
	for _, b := range s {
		if b != 0 {
			return false
		}
	}
	return true
}

func (s subKey) Bytes() []byte {
	return s[:]
}

// a key is two (specifically one encryption and one signing) subKeys
type key [2]subKey

func (k key) IsZero() bool {
	return k[0].IsZero() && k[1].IsZero()
}

// a keyPair is two keys. One public, one private
type keyPair [2]key

func (kp keyPair) IsZero() bool {
	return kp[0].IsZero() && kp[1].IsZero()
}

/**
 * Layout:
 *	1st 32 bytes:	public	encrpytion key
 *	2nd 32 bytes:	public	signing	key
 *	3rd 32 bytes:	private encryption key
 *	4th 32 bytes:	private signing key
 **/

func (k key) Bytes() []byte {
	b := make([]byte, 2*subKeySize)
	copy(b[:subKeySize], k[0][:])
	copy(b[subKeySize:], k[1][:])
	return b
}

func (k key) Signing() subKey {
	return k[1]
}

func (k key) Encryption() subKey {
	return k[0]
}

func (k keyPair) Bytes() []byte {
	b := make([]byte, 4*subKeySize)
	copy(b[:2*subKeySize], k[0].Bytes()) // public
	copy(b[2*subKeySize:], k[1].Bytes()) // private
	return b
}

func KeyFromBytes(b []byte) key {
	if len(b) != subKeySize {
		panic("wrong length for key")
	}
	k := key{}
	copy(k[0][:], b[:subKeySize])
	copy(k[1][:], b[subKeySize:])
	return k
}

func NewSubKey(randy io.Reader) subKey {
	sk := subKey{}
	randy.Read(sk[:])
	return sk
}

func NewKey(randy io.Reader) key {
	return key{NewSubKey(randy), NewSubKey(randy)}
}

func NewKeyPair(randy io.Reader) keyPair {

	/**
	 * Layout:
	 *	1st 32 bytes:	public	encrpytion key
	 *	2nd 32 bytes:	public	signing	key
	 *	3rd 32 bytes:	private encryption key
	 *	4th 32 bytes:	private signing key
	 **/

	var kp keyPair

	//	encryption keys
	ed := ecdh.X25519()
	encryptionPriv, err := ed.GenerateKey(randy)
	if err != nil {
		panic(err)
	}
	encryptionPub := encryptionPriv.PublicKey()

	kp[0][0] = subKey(encryptionPub.Bytes())
	kp[1][0] = subKey(encryptionPriv.Bytes())

	//	signing keys
	signPub, signPriv, err := ed25519.GenerateKey(randy)
	if err != nil {
		panic(err)
	}

	kp[0][1] = subKey(signPub)
	kp[1][1] = subKey(signPriv[:subKeySize])

	return kp
}
