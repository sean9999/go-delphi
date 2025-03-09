package main

import (
	"fmt"
	"strings"

	"github.com/sean9999/hermeti"
)

// output pub key
func (a *appstate) msg(env hermeti.Env) {

	if len(env.Args) < 3 {
		fmt.Fprintln(env.ErrStream, "not enough args")
		return
	}

	msg := strings.Join(env.Args[2:], " ")

	fmt.Fprintln(env.OutStream, msg)

}
