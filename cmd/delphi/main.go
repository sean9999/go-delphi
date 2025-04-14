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

	stuff, err := io.ReadAll(r)

	fmt.Println(string(stuff))
	fmt.Println(err)

	file, ok := r.(*os.File)
	if !ok {
		return false, nil
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

func (a *appstate) Run(env hermeti.Env) {
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

func (a *appstate) init(env hermeti.Env) error {

	var privFile string
	f := flag.NewFlagSet("fset", flag.ExitOnError)
	f.StringVar(&privFile, "priv", "", "private key file")
	f.Parse(env.Args)

	if len(env.Args) >= 2 {
		a.subcommand = env.Args[1]
	}

	switch a.subcommand {
	default:

		has, err := hasStdin(env.InStream)
		if err != nil {
			return fmt.Errorf("could not initialize: %w", err)
		}
		if has {
			// read in all pems
			inBytes, readerr := io.ReadAll(env.InStream)
			if readerr != nil {
				return readerr
			}
			thispem, remainder := readNextPem(inBytes)
			for thispem != nil {
				a.pems[delphi.Subject(thispem.Type)] = append(a.pems[delphi.Subject(thispem.Type)], *thispem)
				thispem, remainder = readNextPem(remainder)
			}

			// find privkey, pluck it out, attach to "self"
			// selfPem, pems := pluckPriv(a.pems)
			// if selfPem != nil {
			// 	p := new(delphi.Principal)
			// 	err := p.UnmarshalPEM(*selfPem)
			// 	if err != nil {
			// 		return err
			// 	}
			// 	a.self = *p
			// }
			// a.pems = pems
		}

	}

	return nil
}

func main() {

	defer func() {
		if r := recover(); r != nil {
			fmt.Println("PANIC:", r)
		}
	}()

	state := new(appstate)
	cli := hermeti.NewRealCli[*appstate](state)
	err := state.init(cli.Env)
	if err != nil {
		panic(err)
	}
	cli.Run()

}
