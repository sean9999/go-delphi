package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/sean9999/go-delphi"
	"github.com/sean9999/hermeti"
)

func hasStdin(r io.Reader) (bool, error) {

	// stuff, err := io.ReadAll(r)

	// fmt.Println(string(stuff))
	// fmt.Println(err)

	file, isFile := r.(*os.File)
	if !isFile {
		return (r != nil), nil
	}
	fi, err := file.Stat()
	if err != nil {
		return false, err
	}
	size := fi.Size()
	if size > 0 {
		return true, nil
	} else {
		return false, nil
	}
}

type delphiApp struct {
	self       delphi.Principal
	subcommand string
	pems       pemBag
	inputBuf   io.ReadWriter
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
	case "msg":
		app.msg(env)
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
	case "echo":
		app.echo(env)
	default:
		fmt.Fprintf(env.ErrStream, "no subcommand called %q\n", app.subcommand)
	}
}

// Init initializes a *delphiApp, preparing it for [Run]
func (app *delphiApp) Init(env hermeti.Env) error {

	var privFile string
	f := flag.NewFlagSet("fset", flag.ExitOnError)
	f.StringVar(&privFile, "priv", "", "private key file")
	f.Parse(env.Args)

	if len(env.Args) >= 2 {
		app.subcommand = env.Args[1]
	}

	app.pems = make(pemBag)

	switch app.subcommand {
	default:

		//has, err := hasStdin(env.InStream)
		//if err != nil {
		//	return fmt.Errorf("could not initialize: %w", err)
		//}

		has := true

		if has {
			// read in all pems and keep them in a bag
			inBytes, readerr := io.ReadAll(env.InStream)
			if readerr != nil {
				return readerr
			}
			thispem, remainder := readNextPem(inBytes)
			for thispem != nil {
				app.pems[delphi.Subject(thispem.Type)] = append(app.pems[delphi.Subject(thispem.Type)], *thispem)
				thispem, remainder = readNextPem(remainder)
			}
			app.inputBuf = bytes.NewBuffer(remainder)
		}
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
