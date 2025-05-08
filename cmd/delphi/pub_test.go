package main

import (
	"testing"

	"github.com/sean9999/hermeti"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
)

func TestPub(t *testing.T) {

	//	cli with testing env
	app := new(delphiApp)
	cli := hermeti.NewTestCli(app)
	cli.Env.Args = []string{"delphi", "pub"}

	//	mount ../../testdata into memory-backed fs
	subfs := afero.NewIOFS(afero.NewBasePathFs(afero.NewOsFs(), "../../testdata"))
	err := cli.Env.Mount(subfs, "./testdata")
	if err != nil {
		t.Fatal(err)
	}

	//	read priv1.pem into stdin
	fd, err := cli.Env.Filesystem.Open("./testdata/bitter-frost.pem")
	if err != nil {
		t.Fatal(err)
	}
	cli.Env.InStream = fd

	//	run cat ./testdata/bitter-frost.pem | delphi pub
	cli.Run()

	o, _ := cli.OutStream()

	assert.Contains(t, o.String(), "GdcBKea7s3wQfGLhYCGzQRbIdZVQi8USkpdXLgFu2CNW")

}
