package main

import (
	"fmt"

	"github.com/sean9999/hermeti"
)

func (app *DelphiApp) create_assertion(env hermeti.Env) {

	if !app.pluckPriv() {
		fmt.Fprintln(env.ErrStream, ErrNoPrivKey)
		return
	}

	msg, err := app.Self.Assert(env.Randomness)

	if err != nil {
		fmt.Fprintln(env.ErrStream, err)
		return
	}

	fmt.Fprintln(env.OutStream, msg)

}
