package main

import (
	"encoding/pem"
	"fmt"

	"github.com/sean9999/go-delphi"
	"github.com/sean9999/hermeti"
)

func (a *appstate) create(env hermeti.Env) {

	p := delphi.NewPrincipal(env.Randomness)

	pemFile, err := p.MarhsalPEM()
	if err != nil {
		fmt.Fprintln(env.ErrStream, err)
		return
	}

	pemBytes := pem.EncodeToMemory(&pemFile)

	fmt.Fprintln(env.OutStream, string(pemBytes))

}
