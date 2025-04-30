package main

import (
	"fmt"
	"strings"

	"io"

	"github.com/sean9999/go-delphi"
	"github.com/sean9999/hermeti"
)

// take in some data and return a PEM where that data is the body
func (a *delphiApp) msg(env hermeti.Env) {

	if len(env.Args) < 3 {
		fmt.Fprintln(env.ErrStream, "not enough args")
		return
	}

	//	ensure line ending
	body := strings.Join(env.Args[2:], " ")
	body = strings.TrimRight(body, "\n") + "\n"

	msg := delphi.NewMessage(env.Randomness, "DELPHI PLAIN MESSAGE", []byte(body))

	msg.SenderKey = a.self.PublicKey()

	io.Copy(env.OutStream, msg)

}
