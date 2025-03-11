package main

import (
	"fmt"
	"strings"

	"io"

	"github.com/sean9999/go-delphi"
	"github.com/sean9999/hermeti"
)

// output pub key
func (a *appstate) msg(env hermeti.Env) {

	if len(env.Args) < 3 {
		fmt.Fprintln(env.ErrStream, "not enough args")
		return
	}

	//	ensure line ending
	body := strings.Join(env.Args[2:], " ")
	body = strings.TrimRight(body, "\n") + "\n"

	msg := delphi.NewMessage(env.Randomness, []byte(body))

	msg.Sender = a.self.PublicKey()

	io.Copy(env.OutStream, msg)

}
