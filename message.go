package delphi

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"

	"github.com/sean9999/pear"
	"github.com/vmihailenco/msgpack/v5"
	omap "github.com/wk8/go-ordered-map/v2"
)

// KV is a key-value store whose keys are ordered, offering deterministic serialization
type KV = omap.OrderedMap[string, string]

func NewKV() *omap.OrderedMap[string, string] {
	kv := omap.New[string, string]()
	return kv
}

var ErrNotImplemented = errors.New("not implemented")

// a Message is a message that represents either plain text or cipher text,
// encapsulating all data and metadata necessary to perform cryptographic operations.
type Message struct {
	readBuffer []byte `msgpack:"-"`
  Subject    string `msgpack:"subj" json:"subj"`
  Recipient  Key    `msgpack:"to" json:"to"`
  Sender     Key    `msgpack:"from" json:"from"`
  Headers    *KV    `msgpack:"hdrs" json:"hdrs"` // additional authenticated data (AAD)
  ephPubkey  []byte `msgpack:"ephkey" json:"ephkey"`
  nonce      Nonce  `msgpack:"nonce" json:"nonce"`
  cipherText []byte `msgpack:"ctxt" json:"cipherText"`
  PlainText  []byte `msgpack:"ptxt" json:"plainText"`
  signature  []byte `msgpack:"sig" json:"sig"`
}

// RecipientEncryption() returns the recipient as a public encryption key
func (m *Message) RecipientEncryption() crypto.PublicKey {
	k, err := ecdh.X25519().NewPublicKey(m.Recipient.Encryption().Bytes())
	if err != nil {
		panic(err)
	}
	return k
}

// SenderEncryption() returns the sender as a public encryption key
func (m *Message) SenderEncryption() crypto.PublicKey {
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

// toStringMap converts an ordered set to an unordered map
func toStringMap(msg *Message) map[string]string {
	n := make(map[string]string)

	for pair := msg.Headers.Oldest(); pair != nil; pair = pair.Next() {
		n[pair.Key] = pair.Value
	}

	n["signature"] = fmt.Sprintf("%x", msg.Signature())
	n["nonce"] = fmt.Sprintf("%x", msg.nonce)
	n["from"] = msg.Sender.ToHex()
	return n
}

func (m *Message) ToPEM() pem.Block {

	var b []byte
	if m.Encrypted() {
		b = m.cipherText
	} else {
		b = m.PlainText
	}

	p := pem.Block{
		Type:    m.Subject,
		Headers: toStringMap(m),
		Bytes:   b,
	}
	return p
}

func extractHex(hdrs map[string]string, key string) ([]byte, error) {

	val, exists := hdrs[key]
	if !exists {
		return nil, pear.Errorf("key doesn't exist: %q", key)
	}

	b, err := hex.DecodeString(val)
	if err != nil {
		return nil, pear.Errorf("failed to extract hex: %w", err)
	}

	return b, nil
}

func (m *Message) FromPEM(p pem.Block) error {

	m.Headers = NewKV()

	for k, v := range p.Headers {
		switch k {
		case "nonce":
			nonce, err := extractHex(p.Headers, "nonce")
			if err != nil {
				return err
			}
			m.nonce = Nonce(nonce)
		case "signature":
			sig, err := extractHex(p.Headers, "signature")
			if err != nil {
				return err
			}
			m.signature = sig
		case "from":
			pubKeyBytes, err := extractHex(p.Headers, "from")
			if err != nil {
				return err
			}
			m.Sender = Key{}.From(pubKeyBytes)
		default:
			m.Headers.Set(k, v)
		}

	}

	m.Subject = p.Type
	m.PlainText = p.Bytes
	return nil
}

func (m *Message) String() string {
	p := m.ToPEM()
	pemBytes := pem.EncodeToMemory(&p)
	return string(pemBytes)
}

func (m *Message) Read(b []byte) (int, error) {
	if m.readBuffer == nil {
		p := m.ToPEM()
		m.readBuffer = pem.EncodeToMemory(&p)
	}
	if len(m.readBuffer) > 0 {
		bytesWritten := copy(b, m.readBuffer)
		m.readBuffer = m.readBuffer[bytesWritten:]
		return bytesWritten, nil
	} else {
		return 0, io.EOF
	}
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
	sum = append(sum, msg.nonce[:]...)
	if msg.Encrypted() {
		sum = append(sum, msg.cipherText...)
	} else {
		sum = append(sum, msg.PlainText...)
	}

	//	let's no include headers because since the order cannot be known
	//	it's too hard to acheive determinism
	// if msg.Headers.Length() > 0 {
	// 	headers, err := msg.Headers.MarshalBinary()
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	sum = append(sum, headers...)
	// }

	return hash.Sum(sum), nil
}

// msg.Sign(Signer) is another way of doing signer.Sign(*Message)
func (msg *Message) Sign(randy io.Reader, signer crypto.Signer) error {
	var errSign = pear.Defer("could not sign message")
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

// Verify() verifies a signature
func (msg *Message) Verify() bool {
	digest, err := msg.Digest()
	if err != nil {
		panic(err)
	}
	edpub := ed25519.PublicKey(msg.Sender.Signing().Bytes())
	return ed25519.Verify(edpub, digest, msg.signature)
}

// msg.Encrypt(Encrypter) is another way of doing encrypter.Encrypt(*Message)
func (msg *Message) Encrypt(randy io.Reader, encrypter Encrypter, opts EncrypterOpts) error {
	return encrypter.Encrypt(randy, msg, opts)
}

// NewMessage() creates a new Message
func NewMessage(randy io.Reader, plainTxt []byte) *Message {
	msg := new(Message)
	msg.Headers = NewKV()
	msg.ensureNonce(randy)
	msg.PlainText = plainTxt
	return msg
}
