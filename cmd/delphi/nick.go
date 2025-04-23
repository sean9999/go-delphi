package main

import (
	"fmt"

	"github.com/sean9999/hermeti"
)

func (a *appstate) nick(env hermeti.Env) {

	if hasPriv := a.pluckPriv(); !hasPriv {
		fmt.Fprintln(env.ErrStream, "no private key was passed in")
	}

	fmt.Fprintln(env.OutStream, a.self.Nickname())
}
