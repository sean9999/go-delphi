package main

import (
	"encoding/pem"
	"fmt"

	"github.com/sean9999/go-delphi"
	"github.com/sean9999/hermeti"
)

// output pub key
func (app *DelphiApp) pub(env hermeti.Env) {

	if hasPriv := app.pluckPriv(); !hasPriv {
		fmt.Fprintln(env.ErrStream, "no private key was passed in")
	}

	pubkey := app.Self.PublicKey()

	p := pem.Block{
		Type: string(delphi.Pubkey),
		Headers: map[string]string{
			"nick": pubkey.Nickname(),
		},
		Bytes: pubkey.Bytes(),
	}

	err := pem.Encode(env.OutStream, &p)
	if err != nil {
		fmt.Fprintln(env.ErrStream, err)
		return
	}

}
