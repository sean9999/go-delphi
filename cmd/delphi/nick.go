package main

import (
	"fmt"

	"github.com/sean9999/hermeti"
)

func (app *delphiApp) nick(env hermeti.Env) {

	if hasPriv := app.pluckPriv(); !hasPriv {
		fmt.Fprintln(env.ErrStream, "no private key was passed in")
	}

	fmt.Fprintln(env.OutStream, app.self.Nickname())
}
