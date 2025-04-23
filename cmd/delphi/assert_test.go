package main

import (
	"bytes"
	"crypto/rand"
	"encoding/pem"
	"testing"

	"github.com/sean9999/go-delphi"
	"github.com/sean9999/hermeti"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
)

func TestAssert(t *testing.T) {

	//	cli with testing env
	state := new(appstate)
	cli := hermeti.NewTestCli[*appstate](state)
	cli.Env.Args = []string{"delphi", "assert"}
	cli.Env.Randomness = rand.Reader

	//	capture output
	buf := new(bytes.Buffer)
	cli.Env.OutStream = buf

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

	//	run cat ./testdata/priv1.pem | delphi assert
	cli.Run()

	assert.Contains(t, string(buf.Bytes()), "ASSERTION")

	//	pem from bytes
	pem, _ := pem.Decode(buf.Bytes())
	assert.NotNil(t, pem)

	//	msg from pem
	msg := new(delphi.Message)
	err = msg.FromPEM(*pem)

	assert.Equal(t, delphi.Assertion, msg.Subject)

}
