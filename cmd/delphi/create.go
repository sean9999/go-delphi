package main

import (
	"encoding/pem"
	"fmt"

	"github.com/sean9999/go-delphi"
	"github.com/sean9999/hermeti"
)

func (a *delphiApp) create(env hermeti.Env) {

	if a.pems.Has(delphi.Privkey) {
		fmt.Fprintln(env.ErrStream, "You passed in a private key. This operation is all about creating one.")
		return
	}

	p := delphi.NewPrincipal(env.Randomness)
	pemFile, err := p.MarhsalPEM()

	//	I don't see how an error is possibe. Nevertheless...
	if err != nil {
		fmt.Fprintln(env.ErrStream, err)
		return
	}

	pemBytes := pem.EncodeToMemory(&pemFile)
	fmt.Fprint(env.OutStream, string(pemBytes))
}
