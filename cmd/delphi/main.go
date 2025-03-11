package main

import (
	"flag"
	"io"

	"github.com/sean9999/go-delphi"
	"github.com/sean9999/hermeti"
)

type appstate struct {
	self       delphi.Principal
	subcommand string
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
	}
}

func (a *appstate) init(env hermeti.Env) error {

	var privFile string
	f := flag.NewFlagSet("fset", flag.ExitOnError)
	f.StringVar(&privFile, "priv", "", "private key file")
	f.Parse(env.Args)

	var keybytes []byte
	var err error
	if len(privFile) > 0 {
		fd, err := env.Filesystem.Open(privFile)
		if err != nil {
			return err
		}
		keybytes, err = io.ReadAll(fd)
	} else {
		keybytes, err = io.ReadAll(env.InStream)
		if err != nil {
			return err
		}
	}

	p, err := delphi.Principal{}.From(keybytes)
	if err != nil {
		return err
	}
	a.self = p
	if len(env.Args) >= 2 {
		a.subcommand = env.Args[1]
	}
	return nil
}

func main() {

	state := new(appstate)
	cli := hermeti.NewRealCli[*appstate](state)
	state.init(cli.Env)
	cli.Run()

}
