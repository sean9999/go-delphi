package main

import (
	"fmt"

	"github.com/sean9999/go-delphi"
	"github.com/sean9999/hermeti"
)

func (app *DelphiApp) Info(env hermeti.Env) {
	fmt.Fprintln(env.OutStream, app.Self.Nickname())
}

func (app *DelphiApp) PluckEncrypted() *delphi.Message {
	p := app.pems.Pluck(delphi.EncryptedMessage)
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

func (app *DelphiApp) decrypt(env hermeti.Env) {

	msg := app.PluckEncrypted()

	if !app.pluckPriv() {
		fmt.Fprintln(env.ErrStream, "no private key. WTF do you expect me to do with that?")
		return
	}

	err := app.Self.Decrypt(msg, nil)
	if err != nil {
		fmt.Fprintln(env.ErrStream, err)
		return
	}

	fmt.Fprintln(env.OutStream, msg)

}
