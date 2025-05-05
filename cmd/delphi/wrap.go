package main

import (
	"io"

	"github.com/sean9999/go-delphi"
	"github.com/sean9999/hermeti"
)

// take in some data and wrap it in a PEM with type "DELPHI PLAIN MESSAGE"
func (a *delphiApp) wrap(env hermeti.Env) {

	body := a.inBuff.Bytes()

	msg := delphi.NewMessage(env.Randomness, "DELPHI PLAIN MESSAGE", body)

	msg.SenderKey = a.self.PublicKey()

	io.Copy(env.OutStream, msg)

}
