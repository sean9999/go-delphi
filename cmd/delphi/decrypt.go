package main

import (
	"fmt"
	"io"

	"github.com/sean9999/go-delphi"

	"github.com/sean9999/hermeti"
)

func (a *delphiApp) Info(env hermeti.Env) {
	fmt.Fprintln(env.OutStream, a.self.Nickname())
}

func (a *delphiApp) decrypt(env hermeti.Env) {

	if len(env.Args) < 3 {
		fmt.Fprintln(env.ErrStream, "must pass filename arg")
		return
	}

	fileName := env.Args[2]

	fd, err := env.Filesystem.Open(fileName)
	if err != nil {
		fmt.Fprintln(env.ErrStream, err)
		return
	}

	msg := new(delphi.Message)
	_, err = io.Copy(fd, msg)
	if err != nil {
		fmt.Fprintln(env.ErrStream, err)
		return
	}

	err = a.self.Decrypt(msg, nil)
	if err != nil {
		fmt.Fprintln(env.ErrStream, err)
		return
	}

	fmt.Fprintln(env.OutStream, string(msg.PlainText))

}
