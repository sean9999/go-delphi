package main

import (
	"encoding/pem"
	"fmt"

	"github.com/sean9999/hermeti"
)

func readNextPem(b []byte) (p *pem.Block, rest []byte) {
	return pem.Decode(b)
}

// show us all the PEMs that have been streamed in.
// output a message to stderr if some data is not PEM
func (a *appstate) enumerate(env hermeti.Env) {

	if !a.self.IsZero() {
		fmt.Fprintln(env.OutStream, "I am ", a.self.Nickname())
	}

	for typ, pemList := range a.pems {
		for i := range pemList {
			fmt.Fprintf(env.OutStream, "pem %d is of type %s\n", i+1, typ)
		}
	}

}
