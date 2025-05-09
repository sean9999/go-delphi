package main

import (
	"io"

	"github.com/sean9999/go-delphi"
	"github.com/sean9999/hermeti"
)

// take in some data and wrap it in a PEM with type "DELPHI PLAIN MESSAGE"
func (app *delphiApp) wrap(env hermeti.Env) {

	body := app.inBuff.Bytes()

	msg := delphi.NewMessage(env.Randomness, "DELPHI PLAIN MESSAGE", body)

	msg.SenderKey = app.self.PublicKey()

	io.Copy(env.OutStream, msg)

}
