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
	state := new(delphiApp)
	cli := hermeti.NewTestCli[*delphiApp](state)
	cli.Env.Args = []string{"delphi", "pub"}

	//	mount ../../testdata into memory-backed fs
	subfs := afero.NewIOFS(afero.NewBasePathFs(afero.NewOsFs(), "../../testdata"))
	cli.Env.Mount(subfs, "./testdata")

	//	read priv1.pem into stdin
	fd, err := cli.Env.Filesystem.Open("./testdata/priv1.pem")
	if err != nil {
		t.Fatal(err)
	}
	cli.Env.InStream = fd

	state.Init(cli.Env)

	//	run cat ./testdata/priv1.pem | delphi pub
	cli.Run()

	//	capture output
	output, err := io.ReadAll(cli.Env.OutStream.(io.Reader))
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, "552610140110ff8aff154a5692c590ad636a900e1174db2e7547d6a3a0f4492697989199f98249fba3032b9434310adbda037e7753a2caf1c69dce3fadab5d3f\n", string(output))

}
