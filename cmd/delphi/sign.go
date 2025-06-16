package main

import (
	"errors"
	"fmt"

	"github.com/sean9999/go-delphi"

	"github.com/sean9999/hermeti"
)

// PluckMessage plucks out a message, be it plain or encrypted, from the [pemBag].
func (app *DelphiApp) PluckMessage() *delphi.Message {
	plainMsg := app.PluckPlain()
	if plainMsg != nil {
		return plainMsg
	}
	encryptedMsg := app.PluckEncrypted()
	if encryptedMsg != nil {
		return encryptedMsg
	}
	return nil
}

// encrypt a PEM-encoded plain message, thereby turning it into an encrypted message
func (app *DelphiApp) sign(env hermeti.Env) {

	//	self
	hasPriv := app.pluckPriv()
	if !hasPriv {
		fmt.Fprintln(env.ErrStream, ErrNoPrivKey)
		return
	}

	//	message
	msg := app.PluckMessage()
	if msg == nil {
		fmt.Fprintln(env.ErrStream, errors.New("no message to sign"))
		return
	}

	//	Attach public key. If we're signing it, we want to say who signed it.
	msg.SenderKey = app.Self.PublicKey()

	//	Attach signature
	err := msg.Sign(env.Randomness, &app.Self)
	if err != nil {
		fmt.Fprintln(env.ErrStream, err)
		return
	}
	fmt.Fprintln(env.OutStream, msg)

}
