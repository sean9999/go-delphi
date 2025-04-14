package main

import (
	"testing"

	"github.com/sean9999/hermeti"
	"github.com/spf13/afero"
)

func TestAssert(t *testing.T) {

	//	cli with testing env
	state := new(appstate)
	cli := hermeti.NewTestCli[*appstate](state)
	cli.Env.Args = []string{"delphi", "assert"}

	//	mount ../../testdata into memory-backed fs
	subfs := afero.NewIOFS(afero.NewBasePathFs(afero.NewOsFs(), "../../testdata"))
	cli.Env.Mount(subfs, "./testdata")

	//	read bitter-frost into stdin
	fd, err := cli.Env.Filesystem.Open("./testdata/bitter-frost.pem")
	if err != nil {
		t.Fatal(err)
	}
	cli.Env.InStream = fd

	state.init(cli.Env)

	//	run cat ./testdata/priv1.bin | delphi pub
	cli.Run()

}
