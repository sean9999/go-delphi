package main

import (
	"bytes"
	"fmt"
	"io"

	"github.com/sean9999/hermeti"
)

// echo whatever was passed in on stdout
func (a *delphiApp) echo(env hermeti.Env) {

	//	cat the decoded body of each PEM
	buf := new(bytes.Buffer)
	for _, pemlist := range a.pems {
		for _, p := range pemlist {
			txt := fmt.Sprintf("%s\n", p.Bytes)
			buf.WriteString(txt)
		}
	}

	io.Copy(env.OutStream, buf)

}
