package main

import (
	"errors"

	"github.com/sean9999/go-delphi"
)

var ErrNoPrivKey = errors.New("no private key")

func (app *delphiApp) pluckPriv() bool {
	selfPem := app.pems.Pluck(delphi.Privkey)
	if selfPem == nil {
		return false
	}

	self := new(delphi.Principal)
	err := self.UnmarshalPEM(*selfPem)
	if err != nil {
		return false
	}
	app.self = *self
	return true
}

var ErrNoRecipient = errors.New("no recipient")
