package main

import (
	"io"
	"testing"

	"github.com/sean9999/hermeti"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
)

func TestNick(t *testing.T) {

	//	cli with testing env
	state := new(appstate)
	cli := hermeti.NewTestCli[*appstate](state)

	//	sub-command / args / flags
	cli.Env.Args = []string{"delphi", "nick"}

	//	mount ../../testdata into memory-backed fs
	subfs := afero.NewIOFS(afero.NewBasePathFs(afero.NewOsFs(), "../../testdata"))
	cli.Env.Mount(subfs, "./testdata")

	//	read priv1.pem into stdin
	fd, err := cli.Env.Filesystem.Open("./testdata/priv1.pem")
	if err != nil {
		t.Fatal(err)
	}
	cli.Env.InStream = fd

	state.init(cli.Env)

	//	run cat ./testdata/priv1.pem | delphi nick
	cli.Run()

	//	capture output
	output, err := io.ReadAll(cli.Env.OutStream.(io.Reader))
	if err != nil {
		t.Error(err)
	}

	//	divine-cloud is the nickname of the all-zero public key.
	assert.NotEqual(t, "divine-cloud\n", string(output))

	//	Principal.Nickname() should be the same as Peer.Nickname()
	nick1 := state.self.Nickname()
	nick2 := state.self.PublicKey().Nickname()
	assert.Equal(t, nick1, nick2)

}
