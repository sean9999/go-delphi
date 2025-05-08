package main

import (
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
	app := new(delphiApp)
	cli := hermeti.NewTestCli(app)
	cli.Env.Args = []string{"delphi", "assert"}
	cli.Env.Randomness = rand.Reader

	//	mount ../../testdata into memory-backed fs
	subFs := afero.NewIOFS(afero.NewBasePathFs(afero.NewOsFs(), "../../testdata"))
	err := cli.Env.Mount(subFs, "./testdata")
	if err != nil {
		t.Fatal(err)
	}

	//	read bitter-frost into stdin
	err = cli.Env.PipeInFile("./testdata/bitter-frost.pem")
	if err != nil {
		t.Fatal(err)
	}

	//	run cat ./testdata/bitter-frost.pem | delphi assert
	cli.Run()

	buf, err := cli.OutStream()
	if err != nil {
		t.Fatal(err)
	}

	assert.Contains(t, string(buf.Bytes()), "ASSERTION")

	//	pem from bytes
	thisPem, _ := pem.Decode(buf.Bytes())
	assert.NotNil(t, thisPem)

	//	msg from thisPem
	msg := new(delphi.Message)
	err = msg.FromPEM(*thisPem)
	assert.NoError(t, err)
	if err != nil {
		t.Fail()
	}

	assert.Equal(t, delphi.Assertion, msg.Subject)

}
