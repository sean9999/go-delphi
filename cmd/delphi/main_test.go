package main_test

import (
	"fmt"
	"strings"

	"github.com/sean9999/go-delphi"
	x "github.com/sean9999/go-delphi/cmd/delphi"
	"github.com/sean9999/hermeti"
)

func Example() {

	//	cli with testing env
	app := new(x.DelphiApp)
	cli := hermeti.NewTestCli(app)

	//	sub-command / args / flags
	cli.Env.Args = []string{"delphi", "nick"}

	//	pipe in a PEM file
	pubkey := delphi.KeyFromHex("72fadf46107f706dd32f19b9c7867f19d70129e6bbb37c107c62e16021b34116c87595508bc5129297572e016ed823564ee5796fb03528cd15e976ab89e1f087")
	msg := delphi.ComposeMessage(nil, delphi.Pubkey, pubkey.Bytes())
	cli.Env.PipeIn(msg)

	cli.Run()

	//	Principal.Nickname() should be the same as Peer.Nickname()
	nick1 := app.Self.Nickname()
	nick2 := app.Self.PublicKey().Nickname()
	diff := strings.Compare(nick1, nick2)

	fmt.Printf("diff = %d\n", diff)
	fmt.Println(nick1)

	//	Output
	//	diff = 0
	//	divine-cloud
}
