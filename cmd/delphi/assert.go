package main

import (
	"fmt"

	"github.com/sean9999/hermeti"
)

func (app *delphiApp) create_assertion(env hermeti.Env) {

	if !app.pluckPriv() {
		fmt.Fprintln(env.ErrStream, ErrNoPrivKey)
		return
	}

	msg, err := app.self.Assert(env.Randomness)

	if err != nil {
		fmt.Fprintln(env.ErrStream, err)
		return
	}

	fmt.Fprintln(env.OutStream, msg)

}
