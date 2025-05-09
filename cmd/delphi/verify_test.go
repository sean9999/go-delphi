package main

import (
	"crypto/rand"
	"testing"

	"github.com/sean9999/hermeti"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
)

func TestVerify(t *testing.T) {

	//	test CLI
	cli := hermeti.NewTestCli(new(delphiApp))
	cli.Env.Args = []string{"delphi", "verify"}
	cli.Env.Randomness = rand.Reader

	//	mount ../../testdata into memory-backed fs
	subFs := afero.NewIOFS(afero.NewBasePathFs(afero.NewOsFs(), "../../testdata"))
	cli.Env.Mount(subFs, "./testdata")

	//	Pipe in signed message
	err := cli.Env.PipeInFile("./testdata/fortune_signed.pem")
	if err != nil {
		t.Fatal(err)
	}

	cli.Run()
	buf, _ := cli.OutStream()
	assert.Contains(t, buf.String(), "ok")

}
