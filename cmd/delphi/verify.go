package main

import (
	"fmt"

	"github.com/sean9999/hermeti"
)

func (a *delphiApp) verify(env hermeti.Env) {
	fmt.Fprintln(env.ErrStream, "not implemented")
}
