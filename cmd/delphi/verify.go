package main

import (
	"fmt"

	"github.com/sean9999/go-delphi"
	"github.com/sean9999/hermeti"
)

func (app *delphiApp) verify(env hermeti.Env) {

	msg := app.PluckMessage()
	if msg == nil {
		fmt.Fprintln(env.ErrStream, delphi.ErrNoMsg)
		return
	}

	ok := msg.Verify()
	if !ok {
		fmt.Fprintln(env.ErrStream, delphi.ErrNoValid)
	} else {
		fmt.Fprintln(env.OutStream, "ok")
	}

}
