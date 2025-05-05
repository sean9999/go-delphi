package main

import (
	"testing"

	"github.com/sean9999/hermeti"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
)

func TestNick(t *testing.T) {

	//	cli with testing env
	app := new(delphiApp)
	cli := hermeti.NewTestCli(app)

	//	sub-command / args / flags
	cli.Env.Args = []string{"delphi", "nick"}

	//	mount ../../testdata into memory-backed fs
	subfs := afero.NewIOFS(afero.NewBasePathFs(afero.NewOsFs(), "../../testdata"))
	cli.Env.Mount(subfs, "./testdata")

	//	read bitter-frost.pem into stdin
	err := cli.Env.PipeInFile("./testdata/bitter-frost.pem")

	cli.Run()

	//	capture output
	output, err := cli.OutStream()
	if err != nil {
		t.Error(err)
	}

	//	divine-cloud is the nickname of the all-zero public key.
	assert.NotEqual(t, "divine-cloud\n", output.String())

	//	Principal.Nickname() should be the same as Peer.Nickname()
	nick1 := app.self.Nickname()
	nick2 := app.self.PublicKey().Nickname()
	assert.Equal(t, nick1, nick2)

}
