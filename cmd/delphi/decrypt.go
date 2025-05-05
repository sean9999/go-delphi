package main

import (
	"fmt"

	"github.com/sean9999/go-delphi"
	"github.com/sean9999/hermeti"
)

func (a *delphiApp) Info(env hermeti.Env) {
	fmt.Fprintln(env.OutStream, a.self.Nickname())
}

func (a *delphiApp) PluckEncrypted() *delphi.Message {
	p := a.pems.Pluck(delphi.EncryptedMessage)
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

func (a *delphiApp) decrypt(env hermeti.Env) {

	msg := a.PluckEncrypted()

	if !a.pluckPriv() {
		fmt.Fprintln(env.ErrStream, "no private key. WTF do you expect me to do with that?")
		return
	}

	err := a.self.Decrypt(msg, nil)
	if err != nil {
		fmt.Fprintln(env.ErrStream, err)
		return
	}

	fmt.Fprintln(env.OutStream, msg)

}
