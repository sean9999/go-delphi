package main

import (
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

type appstate struct {
	self       delphi.Principal
	subcommand string
	pems       pemBag
}

// Run runs an *appstate against a hermiti.Env.
func (a *appstate) Run(env hermeti.Env) {

	//	a.subcommand is gotten from hermeti.Env.Args
	switch a.subcommand {
	case "create":
		a.create(env)
	case "pub":
		a.pub(env)
	case "nick":
		a.nick(env)
	case "msg":
		a.msg(env)
	case "encrypt":
		a.encrypt(env)
	case "decrypt":
		a.decrypt(env)
	case "assert":
		a.create_assertion(env)
	case "verify":
		a.verify(env)
	case "enumerate":
		a.enumerate(env)
	case "unwrap":
		a.unwrap(env)
	default:
		fmt.Fprintf(env.ErrStream, "no subcommand called %q\n", a.subcommand)
	}
}

// init initializes an *appstate with defaults globals
func (a *appstate) init(env hermeti.Env) error {

	var privFile string
	f := flag.NewFlagSet("fset", flag.ExitOnError)
	f.StringVar(&privFile, "priv", "", "private key file")
	f.Parse(env.Args)

	if len(env.Args) >= 2 {
		a.subcommand = env.Args[1]
	}

	a.pems = make(pemBag)

	switch a.subcommand {
	default:

		has, err := hasStdin(env.InStream)
		if err != nil {
			return fmt.Errorf("could not initialize: %w", err)
		}
		if has {
			// read in all pems and keep them in a bag
			inBytes, readerr := io.ReadAll(env.InStream)
			if readerr != nil {
				return readerr
			}
			thispem, remainder := readNextPem(inBytes)
			for thispem != nil {
				a.pems[delphi.Subject(thispem.Type)] = append(a.pems[delphi.Subject(thispem.Type)], *thispem)
				thispem, remainder = readNextPem(remainder)
			}
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

	state := new(appstate)
	cli := hermeti.NewRealCli(state)
	err := state.init(cli.Env)
	if err != nil {
		panic(err)
	}
	cli.Run()

}
