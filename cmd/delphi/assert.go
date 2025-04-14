package main

import (
	"fmt"

	"github.com/sean9999/hermeti"
)

func (a *appstate) create_assertion(env hermeti.Env) {

	if !a.PluckPriv() {
		fmt.Fprintln(env.ErrStream, ErrNoPrivKey)
		return
	}

	msg, err := a.self.Assert(env.Randomness)

	if err != nil {
		fmt.Fprintln(env.ErrStream, err)
		return
	}

	fmt.Fprintln(env.OutStream, msg)

}
