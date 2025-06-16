package main

import (
	"encoding/pem"
	"fmt"

	"github.com/sean9999/go-delphi"
	"github.com/sean9999/hermeti"
)

func (app *DelphiApp) create(env hermeti.Env) {

	if app.pems.Has(delphi.Privkey) {
		fmt.Fprintln(env.ErrStream, "You passed in app private key. This operation is all about creating one.")
		return
	}

	p := delphi.NewPrincipal(env.Randomness)
	pemFile, err := p.MarshalPEM()

	//	I don't see how an error is possibe. Nevertheless...
	if err != nil {
		fmt.Fprintln(env.ErrStream, err)
		return
	}

	app.self = p

	pemBytes := pem.EncodeToMemory(&pemFile)
	fmt.Fprint(env.OutStream, string(pemBytes))
}
