package main

import (
	"fmt"

	"github.com/sean9999/hermeti"
)

func (app *DelphiApp) nick(env hermeti.Env) {

	if hasPriv := app.pluckPriv(); !hasPriv {
		fmt.Fprintln(env.ErrStream, "no private key was passed in")
	}

	fmt.Fprintln(env.OutStream, app.Self.Nickname())
}
