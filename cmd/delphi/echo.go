package main

import (
	"io"

	"github.com/sean9999/hermeti"
)

// echo whatever was passed in on stdout
func (a *delphiApp) echo(env hermeti.Env) {

	io.Copy(env.OutStream, a.inputBuf)

}
