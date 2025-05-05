package delphi

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"slices"
)

const subKeySize = 32

// a subKey is either: a public encryption, public signing, private encryption, or private signing key
type subKey [subKeySize]byte

// a subKey is zero if all it's bytes are zero
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

// a Key is two (specifically one encryption and one signing) subKeys
type Key [2]subKey

func (k Key) MarshalJson() ([]byte, error) {
	str := k.ToHex()
	return []byte(str), nil
}

func (k *Key) UnmarshalJSON(b []byte) error {
	j := KeyFromHex(string(b))
	copy(k[:], j[:])
	return nil
}

// func (k Key) UnmarshalJSON(hexbytes []byte) error {
// 	actualBytes, err := hex.DecodeString(string(hexbytes))
// 	if err != nil {
// 		return err
// 	}
// 	copy(k[:][:], actualBytes)
// 	return nil
// }

func (k Key) MarshalText() ([]byte, error) {
	return []byte(k.ToHex()), nil
}

// a Key is zero if all it's subKeys are zero
func (k Key) IsZero() bool {
	return k[0].IsZero() && k[1].IsZero()
}

func (k Key) From(b []byte) Key {
	var enc subKey
	var sig subKey
	copy(enc[:], b[:subKeySize])
	copy(sig[:], b[subKeySize:])
	var j Key
	j[0] = enc
	j[1] = sig
	return j
}

// a KeyPair is two [Key]s. One public, one private
type KeyPair [2]Key

// a KeyPair is zero if all it's keys are zero
func (kp KeyPair) IsZero() bool {
	return kp[0].IsZero() && kp[1].IsZero()
}

func (k Key) Bytes() []byte {
	b := make([]byte, 2*subKeySize)
	copy(b[:subKeySize], k[0][:])
	copy(b[subKeySize:], k[1][:])
	return b
}

func (k Key) ToInt64() int64 {
	var num int64
	buf := bytes.NewReader(k.Bytes())
	err := binary.Read(buf, binary.BigEndian, &num)
	if err != nil {
		// Handle the error appropriately
	}
	return num
}

func (k Key) Equal(j Key) bool {
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

func (k Key) Signing() subKey {
	return k[1]
}

func (k Key) Encryption() subKey {
	return k[0]
}

func (k KeyPair) Bytes() []byte {
	b := make([]byte, 4*subKeySize)
	copy(b[:2*subKeySize], k[0].Bytes()) // public
	copy(b[2*subKeySize:], k[1].Bytes()) // private
	return b
}

func (k Key) ToHex() string {
	return hex.EncodeToString(k.Bytes())
}

func KeyFromHex(str string) Key {
	bin, err := hex.DecodeString(str)
	if err != nil {
		return Key{}
	}
	return KeyFromBytes(bin)
}

func KeyFromBytes(b []byte) Key {

	gotSize := len(b)
	wantSize := subKeySize * 2

	if gotSize != wantSize {
		panic(fmt.Sprintf("wrong length for key. Wanted %d but got %d", wantSize, gotSize))
	}
	k := Key{}
	copy(k[0][:], b[:subKeySize])
	copy(k[1][:], b[subKeySize:])
	return k
}

func NewSubKey(randy io.Reader) subKey {
	sk := subKey{}
	randy.Read(sk[:])
	return sk
}

func NewKey(randy io.Reader) Key {
	if randy == nil {
		return Key{}
	}
	return Key{NewSubKey(randy), NewSubKey(randy)}
}

// NewKeyPair generates valid ed25519 and X25519 keys
func NewKeyPair(randy io.Reader) KeyPair {

	/**
	 * Layout:
	 *	1st 32 bytes:	public	encrpytion key
	 *	2nd 32 bytes:	public	signing	key
	 *	3rd 32 bytes:	private encryption key
	 *	4th 32 bytes:	private signing key
	 **/

	var kp KeyPair

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
