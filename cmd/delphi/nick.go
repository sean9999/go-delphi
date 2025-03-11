package main

import (
	"fmt"

	"github.com/sean9999/hermeti"
)

func (a *appstate) nick(env hermeti.Env) {
	fmt.Fprintln(env.OutStream, a.self.Nickname())
}
