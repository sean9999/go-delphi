package main

import (
	"errors"
	"fmt"
	"github.com/sean9999/go-delphi"

	"github.com/sean9999/hermeti"
)

// PluckMessage plucks out a message, be it plain or encrypted, from the [pemBag].
func (a *delphiApp) PluckMessage() *delphi.Message {
	plainMsg := a.PluckPlain()
	if plainMsg != nil {
		return plainMsg
	}
	encryptedMsg := a.PluckEncrypted()
	if encryptedMsg != nil {
		return encryptedMsg
	}
	return nil
}

// encrypt a PEM-encoded plain message, thereby turning it into an encrypted message
func (a *delphiApp) sign(env hermeti.Env) {

	//	self
	hasPriv := a.pluckPriv()
	if !hasPriv {
		fmt.Fprintln(env.ErrStream, ErrNoPrivKey)
		return
	}

	//	message
	msg := a.PluckMessage()
	if msg == nil {
		fmt.Fprintln(env.ErrStream, errors.New("no message to sign"))
		return
	}

	//	Attach public key. If we're signing it, we want to say who signed it.
	msg.SenderKey = a.self.PublicKey()

	//	Attach signature
	err := msg.Sign(env.Randomness, &a.self)
	if err != nil {
		fmt.Fprintln(env.ErrStream, err)
		return
	}
	fmt.Fprintln(env.OutStream, msg)

}
