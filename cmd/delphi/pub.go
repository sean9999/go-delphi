package main

import (
	"fmt"

	"github.com/sean9999/hermeti"
)

// output pub key
func (a *appstate) pub(env hermeti.Env) {
	pubkey := a.self.PublicKey()
	fmt.Fprintln(env.OutStream, pubkey.ToHex())
}
