package main

import (
	"errors"
	"fmt"

	"github.com/sean9999/go-delphi"
	"github.com/sean9999/hermeti"
)

// find and return from all PEMs in bag, a public key. return it as such
func (a *delphiApp) PluckPeer() (pubkey delphi.Key) {
	_recipientPem := a.pems.Pluck(delphi.Pubkey)
	if _recipientPem != nil {
		pubkey = delphi.KeyFromHex(string(_recipientPem.Bytes))
	}
	return pubkey
}

func (a *delphiApp) PluckPlain() *delphi.Message {
	p := a.pems.Pluck(delphi.PlainMessage)
	if p == nil {
		return nil
	}
	msg := new(delphi.Message)
	err := msg.FromPEM(*p)
	if err != nil {
		return nil
	}
	return msg
}

// encrypt a PEM-encoded plain message, thereby turning it into an encrypted message
func (a *delphiApp) encrypt(env hermeti.Env) {

	//	self
	hasPriv := a.pluckPriv()
	if !hasPriv {
		fmt.Fprintln(env.ErrStream, ErrNoPrivKey)
		return
	}

	//	recipient
	recipient := a.PluckPeer()
	if recipient.IsZero() {
		fmt.Fprintln(env.ErrStream, ErrNoRecipient)
		return
	}

	//	message
	msg := a.PluckPlain()
	if msg == nil {
		fmt.Fprintln(env.ErrStream, errors.New("nothing to encrypt"))
		return
	}

	msg.RecipientKey = recipient
	msg.SenderKey = a.self.PublicKey()

	err := a.self.Encrypt(env.Randomness, msg, nil)
	if err != nil {
		fmt.Fprintln(env.ErrStream, err)
		return
	}
	fmt.Fprintln(env.OutStream, msg)
}
