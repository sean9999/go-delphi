package delphi

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

// a "key" in this world encapsulates both encryption and signing subKeys
type key [2]subKey

func (k key) IsZero() bool {
	return k[0].IsZero() && k[1].IsZero()
}

// type pubKey = key
// type privKey = key

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

func (k keyPair) Bytes() []byte {
	b := make([]byte, 4*subKeySize)
	copy(b[:2*subKeySize], k[0].Bytes())
	copy(b[2*subKeySize:], k[1].Bytes())
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
