package main

import (
	"io"
	"testing"

	"github.com/sean9999/hermeti"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
)

func TestPub(t *testing.T) {

	//	cli with testing env
	state := new(appstate)
	cli := hermeti.NewTestCli[*appstate](state)
	cli.Env.Args = []string{"delphi", "pub"}

	//	mount ../../testdata into memory-backed fs
	subfs := afero.NewIOFS(afero.NewBasePathFs(afero.NewOsFs(), "../../testdata"))
	cli.Env.Mount(subfs, "./testdata")

	//	read priv1.bin into stdin
	fd, err := cli.Env.Filesystem.Open("./testdata/priv1.bin")
	if err != nil {
		t.Fatal(err)
	}
	cli.Env.InStream = fd

	state.init(cli.Env)

	//	run cat ./testdata/priv1.bin | delphi pub
	cli.Run()

	//	capture output
	output, err := io.ReadAll(cli.Env.OutStream.(io.Reader))
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, "bd35f721c26b36bdf163d69816d6ee7c90de8b63538807753d024c2d6d581513154b70722fef4cddb36ce3851d02113a539a6ed13315c3da459121db2a5695ca\n", string(output))

}
