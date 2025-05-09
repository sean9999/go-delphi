package main

import (
	"fmt"
	"github.com/sean9999/hermeti"
	"github.com/sean9999/pear"
)

var ErrNoMsg = pear.Defer("no message")
var ErrNoValid = pear.Defer("no valid signature")

func (app *delphiApp) verify(env hermeti.Env) {

	//if !app.pluckPriv() {
	//	fmt.Fprintln(env.ErrStream, ErrNoPrivKey)
	//	return
	//}

	msg := app.PluckMessage()
	if msg == nil {
		fmt.Fprintln(env.ErrStream, ErrNoMsg)
		return
	}

	ok := msg.Verify()
	if !ok {
		fmt.Fprintln(env.ErrStream, ErrNoValid)
	} else {
		fmt.Fprintln(env.OutStream, "ok")
	}

}
