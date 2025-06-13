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
const Version = "v1"

var ErrNotImplemented = errors.New("not implemented")

// a Message is a message that represents either plain text or cipher text,
// encapsulating all data and metadata necessary to perform cryptographic operations.
type Message struct {
	readBuffer   []byte  `msgpack:"-"`
	Subject      Subject `msgpack:"subj" json:"subj"`
	RecipientKey KeyPair `msgpack:"to" json:"to"`
	SenderKey    KeyPair `msgpack:"from" json:"from"`
	Headers      KV      `msgpack:"hdrs" json:"hdrs"` // additional authenticated data (AAD)
	Eph          []byte  `msgpack:"eph" json:"eph"`
	Nonce        Nonce   `msgpack:"nonce" json:"nonce"`
	CipherText   []byte  `msgpack:"ciph" json:"ciph"`
	PlainText    []byte  `msgpack:"plain" json:"plain"`
	Sig          []byte  `msgpack:"sig" json:"sig"`
}

// RecipientEncryption() returns the recipient as a public encryption key (ECDH)
func (msg *Message) RecipientEncryption() crypto.PublicKey {
	k, err := ecdh.X25519().NewPublicKey(msg.RecipientKey.Encryption().Bytes())
	if err != nil {
		panic(err)
	}
	return k
}

// Sender() returns the sender as a public encryption key (ECDH)
func (msg *Message) Sender() crypto.PublicKey {
	k, err := ecdh.X25519().NewPublicKey(msg.SenderKey.Encryption().Bytes())
	if err != nil {
		panic(err)
	}
	return k
}

// Ephemeral() returns the ephemeral key (X25519)
func (msg *Message) Ephemeral() crypto.PublicKey {
	return ed25519.PublicKey(msg.Eph)
}

// Signatory() returns the public signing key of the sender (X25519)
func (msg *Message) Signatory() crypto.PublicKey {
	k, err := ecdh.X25519().NewPublicKey(msg.SenderKey.Signing().Bytes())
	if err != nil {
		panic(err)
	}
	return k
}

// ensureNonce ensures the Message has a [Nonce], and returns it.
func (msg *Message) ensureNonce(randy io.Reader) Nonce {
	if !msg.Nonce.IsZero() {
		return msg.Nonce
	}
	nonce := Nonce{}
	i, err := randy.Read(nonce[:])
	if i != NonceSize {
		panic("wrong length")
	}
	if err != nil {
		panic("error reading from randy into nonce")
	}
	msg.Nonce = nonce
	return msg.Nonce
}

func (msg *Message) MarshalBinary() ([]byte, error) {
	return msgpack.Marshal(msg)
}

func (msg *Message) UnmarshalBinary(p []byte) error {
	return msgpack.Unmarshal(p, msg)
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

func (msg *Message) ToPEM() pem.Block {

	//	ensure message type is correct
	var body []byte
	if msg.Encrypted() {
		body = msg.CipherText
	} else {
		body = msg.PlainText
	}

	hdrs := msg.Headers
	hdrs["delphi/version"] = "v1"

	if !msg.RecipientKey.IsZero() {
		hdrs["to"] = base64.StdEncoding.EncodeToString(msg.RecipientKey.Bytes())
	}
	if !msg.SenderKey.IsZero() {
		hdrs["from"] = base64.StdEncoding.EncodeToString(msg.SenderKey.Bytes())
	}
	if len(msg.Eph) > 0 {
		hdrs["eph"] = base64.StdEncoding.EncodeToString(msg.Eph)
	}
	if !msg.Nonce.IsZero() {
		hdrs["nonce"] = base64.StdEncoding.EncodeToString(msg.Nonce.Bytes())
	}
	if len(msg.Sig) > 0 {
		hdrs["sig"] = base64.StdEncoding.EncodeToString(msg.Sig)
	}

	p := pem.Block{
		Type:    string(msg.Subject),
		Headers: hdrs,
		Bytes:   body,
	}
	return p
}

func (msg *Message) FromPEM(p pem.Block) error {

	msg.Headers = make(KV)

	for k, v := range p.Headers {
		switch k {
		case "nonce":
			bin, err := extractB64(p.Headers, "nonce")
			if err != nil {
				return err
			}
			msg.Nonce = Nonce(bin)
		case "sig":
			bin, err := extractB64(p.Headers, "sig")
			if err != nil {
				return err
			}
			msg.Sig = bin
		case "from":
			pubKeyBytes, err := extractB64(p.Headers, "from")
			if err != nil {
				return err
			}
			msg.SenderKey = KeyPair{}.From(pubKeyBytes)
		case "to":
			pubKeyBytes, err := extractB64(p.Headers, "to")
			if err != nil {
				return err
			}
			msg.RecipientKey = KeyPair{}.From(pubKeyBytes)
		case "eph":
			bin, err := extractB64(p.Headers, "eph")
			if err != nil {
				return err
			}
			msg.Eph = bin
		default:
			msg.Headers[k] = v
		}
	}

	msg.Subject = Subject(p.Type)

	switch p.Type {
	case string(EncryptedMessage):
		msg.CipherText = p.Bytes
	case string(PlainMessage):
		msg.PlainText = p.Bytes
	default:
		//	any type other than EncryptedMessage is treated as plain text.
		msg.PlainText = p.Bytes
	}
	return nil
}

func (msg *Message) String() string {
	p := msg.ToPEM()
	pemBytes := pem.EncodeToMemory(&p)
	return string(pemBytes)
}

func (msg *Message) Read(b []byte) (int, error) {
	if msg.readBuffer == nil {
		p := msg.ToPEM()
		msg.readBuffer = pem.EncodeToMemory(&p)
	}
	if len(msg.readBuffer) > 0 {
		bytesWritten := copy(b, msg.readBuffer)
		msg.readBuffer = msg.readBuffer[bytesWritten:]
		return bytesWritten, nil
	} else {
		return 0, io.EOF
	}
}

func (msg *Message) Write(b []byte) (int, error) {
	if msg == nil {
		return 0, io.EOF
	}
	pm, _ := pem.Decode(b)
	if pm == nil {
		return 0, errors.New("nil message")
	}
	msg.Subject = Subject(pm.Type)
	err := msg.FromPEM(*pm)
	if err != nil {
		return 0, err
	}
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

var ErrInvalidMsg = pear.Defer("invalid message")
var ErrNoNonce = pear.Defer("zero value nonce")
var ErrNoSender = pear.Defer("no sender")

// Digest returns a hash of the Message fields which should be hashed.
func (msg *Message) Digest() ([]byte, error) {

	//	Some fields are included. Some are required. Some are intentionally omitted.
	//	TODO: Consider if SenderKey belongs here.

	hash := sha256.New()

	if !msg.Valid() {
		return nil, ErrInvalidMsg
	}
	if msg.Nonce.IsZero() {
		return nil, ErrNoNonce
	}
	if msg.SenderKey.IsZero() {
		return nil, ErrNoSender
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

var ErrNoSign = pear.Defer("could not sign message")
var ErrNoMsg = pear.Defer("no message")
var ErrNoValid = pear.Defer("no valid signature")

// Sign signs a [Message]
func (msg *Message) Sign(randy io.Reader, signer crypto.Signer) error {
	if randy == nil {
		return pear.New("a source of randomness was not passed in")
	}
	msg.ensureNonce(randy)
	digest, err := msg.Digest()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrNoSign, err)
	}
	sig, err := signer.Sign(randy, digest, nil)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrNoSign, err)
	}
	//msg.Headers.Set(keyspace, "sig", fmt.Sprintf("%x", sig))
	msg.Sig = sig
	return nil
}

// Verify verifies the signature on a [Message]
func (msg *Message) Verify() bool {
	digest, err := msg.Digest()
	if err != nil {
		panic(err)
	} // TODO: do we really want to panic here?
	pubKey := ed25519.PublicKey(msg.SenderKey.Signing().Bytes())
	return ed25519.Verify(pubKey, digest, msg.Sig)
}

// Encrypt encrypts a message to a [Peer]
func (msg *Message) Encrypt(randy io.Reader, encrypter Encrypter, recipient Peer, opts EncrypterOpts) error {
	if recipient.IsZero() {
		return fmt.Errorf("no recipient key. %w. %w", ErrBadKey, ErrDelphi)
	}
	msg.ensureNonce(randy)
	err := encrypter.Encrypt(randy, msg, recipient, opts)
	if err == nil {
		msg.Subject = EncryptedMessage
	} else {
		return err
	}
	return nil
}

// NewMessage creates a new Message. If you pass in a source of randomness, it will have a [Nonce].
func NewMessage(randy io.Reader, subj Subject, plainTxt []byte) *Message {
	msg := new(Message)
	msg.Headers = make(KV)
	msg.PlainText = plainTxt
	msg.Subject = subj
	if randy != nil {
		msg.ensureNonce(randy)
	}
	return msg
}
