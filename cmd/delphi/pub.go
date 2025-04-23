package main

import (
	"fmt"

	"github.com/sean9999/hermeti"
)

// output pub key
func (a *appstate) pub(env hermeti.Env) {

	if hasPriv := a.pluckPriv(); !hasPriv {
		fmt.Fprintln(env.ErrStream, "no private key was passed in")
	}

	pubkey := a.self.PublicKey()
	fmt.Fprintln(env.OutStream, pubkey.ToHex())
}
