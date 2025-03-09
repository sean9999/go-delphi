package main

import (
	"context"
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
	case "pub":
		a.pub(env)
	case "msg":
		a.msg(env)
	case "encrypt":
		a.encrypt(env)
	}
}

func (a *appstate) init(env hermeti.Env) error {

	var privFile string
	f := flag.NewFlagSet("danny", flag.ExitOnError)
	f.StringVar(&privFile, "priv", "", "private key file")

	// fd, err := env.Filesystem.Open(privFile)

	keybytes, err := io.ReadAll(env.InStream)
	if err != nil {
		return err
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
	ctx := context.Background()
	cli.Run(ctx)

}
