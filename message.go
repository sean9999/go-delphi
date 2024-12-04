package delphi

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	stablemap "github.com/sean9999/go-stable-map"
	"github.com/vmihailenco/msgpack/v5"
)

var ErrNotImplemented = errors.New("not implemented")

// a Message is a message that represents either plain text or cipher text,
// encapsulating all data and metadata necessary to perform cryptographic operations.
type Message struct {
	Recipient  Key                                  `msgpack:"to"`
	Sender     Key                                  `msgpack:"from"`
	Headers    *stablemap.StableMap[string, []byte] `msgpack:"hdrs"` // additional authenticated data (AAD)
	ephPubkey  []byte                               `msgpack:"ephkey"`
	nonce      Nonce                                `msgpack:"nonce"`
	cipherText []byte                               `msgpack:"ctxt"`
	PlainText  []byte                               `msgpack:"ptxt"`
	signature  []byte                               `msgpack:"sig"`
}

// To() returns the recipient as a public encryption key
func (m *Message) To() crypto.PublicKey {
	k, err := ecdh.X25519().NewPublicKey(m.Recipient.Encryption().Bytes())
	if err != nil {
		panic(err)
	}
	return k
}

// From() returns the sender as a public encryption key
func (m *Message) From() crypto.PublicKey {
	k, err := ecdh.X25519().NewPublicKey(m.Sender.Encryption().Bytes())
	if err != nil {
		panic(err)
	}
	return k
}

// Ephemeral() returns the value of the ephemeral X25519 key attached to an encrypted Message
func (m *Message) Ephemeral() crypto.PublicKey {
	return ed25519.PublicKey(m.ephPubkey)
}

// Signatory() returns the public signing key of the sender
func (m *Message) Signatory() crypto.PublicKey {

	k, err := ecdh.X25519().NewPublicKey(m.Sender.Signing().Bytes())
	if err != nil {
		panic(err)
	}
	return k
}

func (m *Message) Signature() []byte {
	return m.signature
}

// ensureNonce ensures the Message has a [Nonce]
func (m *Message) ensureNonce(randy io.Reader) Nonce {
	if !m.nonce.IsZero() {
		return m.nonce
	}
	nonce := Nonce{}
	i, err := randy.Read(nonce[:])
	if i != NonceSize {
		panic("wrong length")
	}
	if err != nil {
		panic("error reading from randy into nonce")
	}
	m.nonce = nonce
	return m.nonce
}

func (m *Message) MarshalBinary() ([]byte, error) {
	return msgpack.Marshal(m)
}

func (m *Message) UnmarshalBinary(p []byte) error {
	return msgpack.Unmarshal(p, m)
}

func (msg *Message) Plain() bool {
	return len(msg.PlainText) > 0
}

func (msg *Message) Encrypted() bool {
	return len(msg.cipherText) > 0
}

func (msg *Message) Valid() bool {
	//	TODO: other requirements surely should be
	return (msg.Plain() && !msg.Encrypted()) || (msg.Encrypted() && !msg.Plain())
}

// Digest() returns that portion of a Message which should be hashed and signed
func (msg *Message) Digest() ([]byte, error) {

	//	Some fields are included. Some are required. Some are intentially omitted:
	//	To is omitted. A messages digest is the same regardless of who it's sent to.
	//	From is required. Who its from is integral.
	//	Headers are included if they exists, but not if not. They are treated as AAD.
	//	Nonce is required, to ensure uniqueness
	//	Ephemeral Key is omitted. Nonce provides all necessary randomness
	//	Either plain or cipher text is included. It's an error to have both or neither.

	hash := sha256.New()

	if !msg.Valid() {
		return nil, errors.New("message is not valid")
	}
	if msg.nonce.IsZero() {
		return nil, errors.New("nonce is zero")
	}
	if msg.Sender.IsZero() {
		return nil, errors.New("From is zero")
	}

	sum := make([]byte, 0)
	sum = append(sum, msg.Sender.Bytes()...)
	headers, err := msg.Headers.MarshalBinary()
	if err != nil {
		return nil, err
	}
	sum = append(sum, headers...)
	sum = append(sum, msg.nonce[:]...)

	if msg.Encrypted() {
		sum = append(sum, msg.cipherText...)
	} else {
		sum = append(sum, msg.PlainText...)
	}

	return hash.Sum(sum), nil
}

// msg.Sign(Signer) is another way of doing signer.Sign(*Message)
func (msg *Message) Sign(randy io.Reader, signer crypto.Signer) error {
	var errSign = errors.New("could not sign message")
	msg.ensureNonce(randy)
	digest, err := msg.Digest()
	if err != nil {
		return fmt.Errorf("%w: %w", errSign, err)
	}
	sig, err := signer.Sign(randy, digest, nil)
	if err != nil {
		return fmt.Errorf("%w: %w", errSign, err)
	}
	msg.signature = sig
	return nil
}

// msg.Encrypt(Encrypter) is another way of doing encrypter.Encrypt(*Message)
func (msg *Message) Encrypt(randy io.Reader, encrypter Encrypter, opts EncrypterOpts) error {
	return encrypter.Encrypt(randy, msg, opts)
}

// NewMessage() creates a new Message
func NewMessage(randy io.Reader, plainTxt []byte) *Message {
	msg := new(Message)
	msg.Headers = stablemap.New[string, []byte]()
	msg.ensureNonce(randy)
	msg.PlainText = plainTxt
	return msg
}
