package main

import (
	"io"

	"github.com/sean9999/go-delphi"
	"github.com/sean9999/hermeti"
)

// take in some data and return a PEM where that data is the body
func (a *delphiApp) msg(env hermeti.Env) {

	body := a.inBuff.Bytes()

	msg := delphi.NewMessage(env.Randomness, "DELPHI PLAIN MESSAGE", body)

	msg.SenderKey = a.self.PublicKey()

	io.Copy(env.OutStream, msg)

}
