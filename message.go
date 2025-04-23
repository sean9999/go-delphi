package delphi

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"

	"github.com/sean9999/pear"
	"github.com/vmihailenco/msgpack/v5"
)

// the prefix for header keys
const Keyspace = "delphi"

var ErrNotImplemented = errors.New("not implemented")

// a Message is a message that represents either plain text or cipher text,
// encapsulating all data and metadata necessary to perform cryptographic operations.
type Message struct {
	readBuffer   []byte  `msgpack:"-"`
	Subject      Subject `msgpack:"subj" json:"subj"`
	RecipientKey Key     `msgpack:"to" json:"to"`
	SenderKey    Key     `msgpack:"from" json:"from"`
	Headers      KV      `msgpack:"hdrs" json:"hdrs"` // additional authenticated data (AAD)
	Eph          []byte  `msgpack:"eph" json:"eph"`
	Nonce        Nonce   `msgpack:"nonce" json:"nonce"`
	CipherText   []byte  `msgpack:"ciph" json:"ciph"`
	PlainText    []byte  `msgpack:"plain" json:"plain"`
	Sig          []byte  `msgpack:"sig" json:"sig"`
}

// RecipientEncryption() returns the recipient as a public encryption key
func (m *Message) RecipientEncryption() crypto.PublicKey {
	k, err := ecdh.X25519().NewPublicKey(m.RecipientKey.Encryption().Bytes())
	if err != nil {
		panic(err)
	}
	return k
}

// Sender() returns the sender as a public encryption key (ECDH)
func (m *Message) Sender() crypto.PublicKey {
	k, err := ecdh.X25519().NewPublicKey(m.SenderKey.Encryption().Bytes())
	if err != nil {
		panic(err)
	}
	return k
}

// Ephemeral() returns the ephemeral key (X25519)
func (m *Message) Ephemeral() crypto.PublicKey {
	return ed25519.PublicKey(m.Eph)
}

// Signatory() returns the public signing key of the sender (X25519)
func (m *Message) Signatory() crypto.PublicKey {
	k, err := ecdh.X25519().NewPublicKey(m.SenderKey.Signing().Bytes())
	if err != nil {
		panic(err)
	}
	return k
}

// ensureNonce ensures the Message has a [Nonce]
func (m *Message) ensureNonce(randy io.Reader) Nonce {
	if !m.Nonce.IsZero() {
		return m.Nonce
	}
	nonce := Nonce{}
	i, err := randy.Read(nonce[:])
	if i != NonceSize {
		panic("wrong length")
	}
	if err != nil {
		panic("error reading from randy into nonce")
	}
	m.Nonce = nonce
	return m.Nonce
}

func (m *Message) MarshalBinary() ([]byte, error) {
	return msgpack.Marshal(m)
}

func (m *Message) UnmarshalBinary(p []byte) error {
	return msgpack.Unmarshal(p, m)
}

// type msgBody struct {
// 	To    Key    `json:"to,omitzero,format:hex"`
// 	From  Key    `json:"from,omitzero,format:hex"`
// 	Eph   []byte `json:"eph,omitzero,format:hex"`
// 	Nonce Nonce  `json:"nonce,omitzero,format:hex"`
// 	Ciph  []byte `json:"ciph,omitzero,format:base64"`
// 	Plain []byte `json:"plain,omitzero,format:base64"`
// 	Sig   []byte `json:"sig,omitzero,format:base64"`
// }

// func (m *Message) ToBody() msgBody {
// 	mb := msgBody{
// 		To:    m.Sender,
// 		From:  m.Recipient,
// 		Eph:   m.Eph,
// 		Nonce: m.Nonce,
// 		Ciph:  m.CipherText,
// 		Plain: m.PlainText,
// 		Sig:   m.Sig,
// 	}
// 	return mb
// }

// func fromHex(h []byte) []byte {
// 	b, err := hex.DecodeString(val)
// }

func extractB64(hdrs map[string]string, key string) ([]byte, error) {

	val, exists := hdrs[key]
	if !exists {
		return nil, pear.Errorf("key %q exist", key)
	}

	b, err := base64.StdEncoding.DecodeString(val)
	if err != nil {
		return nil, pear.Errorf("failed to extract: %w", err)
	}

	return b, nil
}

func (m *Message) ToPEM() pem.Block {

	//	ensure message type is correct
	var body []byte
	if m.Encrypted() {
		body = m.CipherText
	} else {
		body = m.PlainText
	}

	hdrs := m.Headers
	hdrs["delphi/version"] = "v1"

	if !m.RecipientKey.IsZero() {
		hdrs["to"] = base64.StdEncoding.EncodeToString(m.RecipientKey.Bytes())
	}
	if !m.SenderKey.IsZero() {
		hdrs["from"] = base64.StdEncoding.EncodeToString(m.SenderKey.Bytes())
	}
	if len(m.Eph) > 0 {
		hdrs["eph"] = base64.StdEncoding.EncodeToString(m.Eph)
	}
	if !m.Nonce.IsZero() {
		hdrs["nonce"] = base64.StdEncoding.EncodeToString(m.Nonce[:])
	}
	if len(m.Sig) > 0 {
		hdrs["sig"] = base64.StdEncoding.EncodeToString(m.Sig)
	}

	p := pem.Block{
		Type:    string(m.Subject),
		Headers: hdrs,
		Bytes:   body,
	}
	return p
}

func (m *Message) FromPEM(p pem.Block) error {

	//m.Headers = make(KV)

	m.Headers = p.Headers

	//	TODO: retire this. These values are now stored in the body. We don't want to overload PEM headers. They should stay light.
	for k, v := range p.Headers {
		switch k {
		case "nonce":
			bin, err := extractB64(p.Headers, "nonce")
			if err != nil {
				return err
			}
			m.Nonce = Nonce(bin)
		case "sig":
			bin, err := extractB64(p.Headers, "sig")
			if err != nil {
				return err
			}
			m.Sig = bin
		case "from":
			pubKeyBytes, err := extractB64(p.Headers, "from")
			if err != nil {
				return err
			}
			m.SenderKey = Key{}.From(pubKeyBytes)
		case "to":
			pubKeyBytes, err := extractB64(p.Headers, "to")
			if err != nil {
				return err
			}
			m.RecipientKey = Key{}.From(pubKeyBytes)
		case "eph":
			bin, err := extractB64(p.Headers, "eph")
			if err != nil {
				return err
			}
			m.Eph = bin
		default:
			m.Headers[k] = v
		}
	}

	m.Subject = Subject(p.Type)

	switch p.Type {
	case string(EncryptedMessage):
		m.CipherText = p.Bytes
	case string(PlainMessage):
	default:
		//	any type other than EncryptedMessage is treated as plain text.
		m.PlainText = p.Bytes
	}
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

func (m *Message) Write(b []byte) (int, error) {
	pm, _ := pem.Decode(b)
	m.Subject = Subject(pm.Type)
	m.PlainText = pm.Bytes
	m.Headers = pm.Headers
	return len(b), io.EOF
}

func (msg *Message) Plain() bool {
	return len(msg.PlainText) > 0
}

func (msg *Message) Encrypted() bool {
	return len(msg.CipherText) > 0
}

func (msg *Message) Valid() bool {
	//	TODO: other requirements surely should be
	return (msg.Plain() && !msg.Encrypted()) || (msg.Encrypted() && !msg.Plain())
}

// Digest() returns that portion of a Message which should be hashed and signed
func (msg *Message) Digest() ([]byte, error) {

	//	Some fields are included. Some are required. Some are intentially omitted.
	//	Consider which should be which

	hash := sha256.New()

	if !msg.Valid() {
		return nil, errors.New("message is not valid")
	}
	if msg.Nonce.IsZero() {
		return nil, errors.New("nonce is zero")
	}
	if msg.SenderKey.IsZero() {
		return nil, errors.New("Sender is zero")
	}

	sum := make([]byte, 0)
	sum = append(sum, msg.SenderKey.Bytes()...)
	sum = append(sum, msg.Nonce[:]...)
	if msg.Encrypted() {
		sum = append(sum, msg.CipherText...)
	} else {
		sum = append(sum, msg.PlainText...)
	}

	for k, v := range msg.Headers.LexicalOrder() {
		sum = append(sum, []byte(k)...)
		sum = append(sum, []byte(v)...)
	}

	return hash.Sum(sum), nil
}

// msg.Sign(Signer) is another way of doing signer.Sign(*Message)
func (msg *Message) Sign(randy io.Reader, signer crypto.Signer) error {

	if randy == nil {
		return pear.New("a source of randomness was not passed in")
	}

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
	//msg.Headers.Set(keyspace, "sig", fmt.Sprintf("%x", sig))
	msg.Sig = sig
	return nil
}

// Verify() verifies a signature
func (msg *Message) Verify() bool {
	digest, err := msg.Digest()
	if err != nil {
		panic(err)
	}
	edpub := ed25519.PublicKey(msg.SenderKey.Signing().Bytes())
	return ed25519.Verify(edpub, digest, msg.Sig)
}

// msg.Encrypt(Encrypter) is another way of doing encrypter.Encrypt(*Message)
func (msg *Message) Encrypt(randy io.Reader, encrypter Encrypter, opts EncrypterOpts) error {
	msg.ensureNonce(randy)
	err := encrypter.Encrypt(randy, msg, opts)
	if err == nil {
		msg.Subject = EncryptedMessage
	} else {
		return err
	}
	return nil
}

// NewMessage() creates a new Message
func NewMessage(randy io.Reader, subj Subject, plainTxt []byte) *Message {
	msg := new(Message)
	msg.Headers = make(KV)
	//msg.ensureNonce(randy)
	msg.PlainText = plainTxt
	msg.Subject = subj
	return msg
}
