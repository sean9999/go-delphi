package main

import (
	"bytes"
	"fmt"
	"io"

	"github.com/sean9999/go-delphi"
	"github.com/sean9999/hermeti"
)

type delphiApp struct {
	self       delphi.Principal
	subcommand string
	pems       pemBag
	inBuff     *bytes.Buffer
}

// Run runs an *appstate against a hermiti.Env.
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
	default:
		fmt.Fprintf(env.ErrStream, "no subcommand called %q\n", app.subcommand)
	}
}

// Init initializes a *delphiApp, preparing it for [Run]
func (app *delphiApp) Init(env hermeti.Env) error {

	if len(env.Args) >= 2 {
		app.subcommand = env.Args[1]
	}

	app.pems = make(pemBag)

	switch app.subcommand {
	default:

		// read in all pems and keep them in a bag
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

func main() {

	//	do something nice and useful with a panic
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("PANIC:", r)
		}
	}()

	state := new(delphiApp)
	cli := hermeti.NewRealCli(state)
	err := state.Init(cli.Env)
	if err != nil {
		panic(err)
	}
	cli.Run()

}
