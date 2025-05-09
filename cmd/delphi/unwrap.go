package main

import (
	"errors"
	"fmt"

	"github.com/sean9999/go-delphi"
	"github.com/sean9999/hermeti"
)

func (app *delphiApp) unwrap(env hermeti.Env) {

	if len(app.pems) == 0 {
		fmt.Fprintln(env.ErrStream, errors.New("no pems"))
		return
	}

	for subj, pems := range app.pems {
		for _, pem := range pems {
			switch subj {
			case delphi.PlainMessage:
				fmt.Fprintf(env.OutStream, "\n%s\n%s\n", pem.Type, pem.Bytes)
			default:
				fmt.Fprintf(env.OutStream, "\n%s\n%x\n", pem.Type, pem.Bytes)
			}
		}
	}
}
