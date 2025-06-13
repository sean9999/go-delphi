package main

import (
	"errors"
	"fmt"

	"github.com/sean9999/go-delphi"
	"github.com/sean9999/hermeti"
)

// PluckPeer plucks out a public key from the [pemBag].
func (app *delphiApp) PluckPeer() (pubkey delphi.KeyPair) {
	peer := app.pems.Pluck(delphi.Pubkey)
	if peer != nil {
		//pubkey = delphi.KeyFromHex(string(peer.Bytes))
		pubkey = delphi.KeyFromBytes(peer.Bytes)
	}
	return pubkey
}

// PluckPlain plucks out a plain message from the [pemBag].
func (app *delphiApp) PluckPlain() *delphi.Message {
	p := app.pems.Pluck(delphi.PlainMessage)
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
func (app *delphiApp) encrypt(env hermeti.Env) {

	//	self
	hasPriv := app.pluckPriv()
	if !hasPriv {
		fmt.Fprintln(env.ErrStream, ErrNoPrivKey)
		return
	}

	//	recipient
	recipient := app.PluckPeer()
	if recipient.IsZero() {
		fmt.Fprintln(env.ErrStream, ErrNoRecipient)
		return
	}

	//	message
	msg := app.PluckPlain()
	if msg == nil {
		fmt.Fprintln(env.ErrStream, errors.New("nothing to encrypt"))
		return
	}

	msg.SenderKey = app.self.PublicKey()

	err := app.self.Encrypt(env.Randomness, msg, recipient, nil)
	if err != nil {
		fmt.Fprintln(env.ErrStream, err)
		return
	}
	fmt.Fprintln(env.OutStream, msg)

}
