package main

import (
	"encoding/pem"
	"fmt"

	"github.com/sean9999/hermeti"
)

func readNextPem(b []byte) (p *pem.Block, rest []byte) {
	return pem.Decode(b)
}

// show us all the PEMs on stdout
// output non PEM data to stderr
func (app *delphiApp) enumerate(env hermeti.Env) {

	fmt.Fprintf(env.OutStream, "number of pems: %d\n\n", len(app.pems))

	if !app.self.IsZero() {
		fmt.Fprintln(env.OutStream, "I am ", app.self.Nickname())
	}

	for typ, pemList := range app.pems {
		for i := range pemList {
			fmt.Fprintf(env.OutStream, "pem %d is of type %s\n", i+1, typ)
		}
	}

}
