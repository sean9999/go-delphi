package delphi

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"slices"
)

const keySize = 32

// a key is either: a public encryption, public signing, private encryption, or private signing key
type key [keySize]byte

// a subKey is zero if all it's bytes are zero
func (s key) IsZero() bool {
	for _, b := range s {
		if b != 0 {
			return false
		}
	}
	return true
}

func (s key) Bytes() []byte {
	return s[:]
}

func NewPeer() Peer {
	return KeyPair{}
}

// a KeyPair is two (specifically one encryption and one signing) keys
type KeyPair [2]key

func (k KeyPair) MarshalJSON() ([]byte, error) {
	str := k.ToHex()
	return json.Marshal(str)
}

func (k KeyPair) MarshalBinary() ([]byte, error) {
	return k.Bytes(), nil
}

func (k *KeyPair) UnmarshalBinary(b []byte) error {
	copy(k[0][:], b[:keySize])
	copy(k[1][:], b[keySize:])
	return nil
}

func (k *KeyPair) UnmarshalJSON(b []byte) error {
	j := KeyFromHex(string(b))
	copy(k[:], j[:])
	return nil
}

func (k KeyPair) MarshalText() ([]byte, error) {
	return []byte(k.ToHex()), nil
}

// a Key is zero if all it's subKeys are zero
func (k KeyPair) IsZero() bool {
	return k[0].IsZero() && k[1].IsZero()
}

func (k KeyPair) From(b []byte) KeyPair {
	var enc key
	var sig key
	copy(enc[:], b[:keySize])
	copy(sig[:], b[keySize:])
	var j KeyPair
	j[0] = enc
	j[1] = sig
	return j
}

// a KeyChain is two [KeyPair]s. One public, one private
type KeyChain [2]KeyPair

// a KeyPair is zero if all it's keys are zero
func (kp KeyChain) IsZero() bool {
	return kp[0].IsZero() && kp[1].IsZero()
}

func (k KeyPair) Bytes() []byte {
	b := make([]byte, 2*keySize)
	copy(b[:keySize], k[0][:])
	copy(b[keySize:], k[1][:])
	return b
}

func (k KeyPair) ToInt64() int64 {
	var num int64
	buf := bytes.NewReader(k.Bytes())
	err := binary.Read(buf, binary.BigEndian, &num)
	if err != nil {
		// Handle the error appropriately
	}
	return num
}

func (k KeyPair) Equal(j KeyPair) bool {
	for i := range 2 {

		jslice := j[i][:]
		kslice := k[i][:]
		same := slices.Equal(jslice, kslice)

		if !same {
			return false
		}

		// if !slices.Equal(k[i][:], j[i][:]) {
		// 	return false
		// }
	}
	return true
}

func (k KeyPair) Signing() key {
	return k[1]
}

func (k KeyPair) Encryption() key {
	return k[0]
}

func (k KeyChain) Bytes() []byte {
	b := make([]byte, 4*keySize)
	copy(b[:2*keySize], k[0].Bytes()) // public
	copy(b[2*keySize:], k[1].Bytes()) // private
	return b
}

func (k KeyPair) ToHex() string {
	return hex.EncodeToString(k.Bytes())
}

func KeyFromHex(str string) KeyPair {
	bin, err := hex.DecodeString(str)
	if err != nil {
		return KeyPair{}
	}
	return KeyFromBytes(bin)
}

func KeyFromBytes(b []byte) KeyPair {

	gotSize := len(b)
	wantSize := keySize * 2

	if gotSize != wantSize {
		panic(fmt.Sprintf("wrong length for key. Wanted %d but got %d", wantSize, gotSize))
	}
	k := KeyPair{}
	copy(k[0][:], b[:keySize])
	copy(k[1][:], b[keySize:])
	return k
}

func NewSubKey(randy io.Reader) key {
	sk := key{}
	randy.Read(sk[:])
	return sk
}

func NewKey(randy io.Reader) KeyPair {
	if randy == nil {
		return KeyPair{}
	}
	return KeyPair{NewSubKey(randy), NewSubKey(randy)}
}

// NewKeyPair generates valid ed25519 and X25519 keys
func NewKeyPair(randy io.Reader) KeyChain {

	/**
	 * Layout:
	 *	1st 32 bytes:	public	encrpytion key
	 *	2nd 32 bytes:	public	signing	key
	 *	3rd 32 bytes:	private encryption key
	 *	4th 32 bytes:	private signing key
	 **/

	var kp KeyChain

	//	encryption keys
	ed := ecdh.X25519()
	encryptionPriv, err := ed.GenerateKey(randy)
	if err != nil {
		panic(err)
	}
	encryptionPub := encryptionPriv.PublicKey()

	kp[0][0] = key(encryptionPub.Bytes())
	kp[1][0] = key(encryptionPriv.Bytes())

	//	signing keys
	signPub, signPriv, err := ed25519.GenerateKey(randy)
	if err != nil {
		panic(err)
	}

	kp[0][1] = key(signPub)
	kp[1][1] = key(signPriv[:keySize])

	return kp
}
