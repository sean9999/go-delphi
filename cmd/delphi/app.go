package main

import (
	"bytes"
	"fmt"
	"github.com/sean9999/go-delphi"
	"github.com/sean9999/hermeti"
	"io"
)

type delphiApp struct {
	self       delphi.Principal
	subcommand string
	pems       pemBag
	inBuff     *bytes.Buffer
}

// Run runs a *delphiApp against a [hermiti.Env].
func (app *delphiApp) Run(env hermeti.Env) {

	//	subcommands come from env.Args
	switch app.subcommand {
	case "create":
		app.create(env)
	case "pub":
		app.pub(env)
	case "nick":
		app.nick(env)
	case "wrap":
		app.wrap(env)
	case "encrypt":
		app.encrypt(env)
	case "decrypt":
		app.decrypt(env)
	case "assert":
		app.create_assertion(env)
	case "verify":
		app.verify(env)
	case "enumerate":
		app.enumerate(env)
	case "unwrap":
		app.unwrap(env)
	case "sign":
		app.sign(env)
	default:
		fmt.Fprintf(env.ErrStream, "no subcommand called %q\n", app.subcommand)
	}
}

// Init prepares a *delphiApp for [Run]nig
func (app *delphiApp) Init(env hermeti.Env) error {

	//	the subcommand is the 2nd arg
	if len(env.Args) >= 2 {
		app.subcommand = env.Args[1]
	}

	//	a pemBag to hold all the pems
	app.pems = make(pemBag)

	switch app.subcommand {
	case "create":
		// create doesn't assume anything was passed in on stdIn
	default:

		// read in all pems
		inBytes, readerr := io.ReadAll(env.InStream)
		if readerr != nil {
			return readerr
		}

		//	capture non pems in buffer
		thispem, remainder := readNextPem(inBytes)
		for thispem != nil {
			app.pems[delphi.Subject(thispem.Type)] = append(app.pems[delphi.Subject(thispem.Type)], *thispem)
			thispem, remainder = readNextPem(remainder)
		}
		app.inBuff = bytes.NewBuffer(remainder)
	}

	return nil
}
