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

func TestEncrypt(t *testing.T) {

	//	cli with testing env
	app := new(delphiApp)
	cli := hermeti.NewTestCli(app)
	cli.Env.Args = []string{"delphi", "encrypt"}
	cli.Env.Randomness = rand.Reader

	//	capture output
	buf := new(bytes.Buffer)
	cli.Env.OutStream = buf

	//	mount ../../testdata into memory-backed fs
	subfs := afero.NewIOFS(afero.NewBasePathFs(afero.NewOsFs(), "../../testdata"))
	cli.Env.Mount(subfs, "./testdata")

	//	pipe recipient, self, and message into stdin

	err := cli.Env.PipeInFile("./testdata/stack.pem")
	if err != nil {
		t.Fatal(err)
	}
	app.Init(cli.Env)

	//	run cat testdata/stack.pem | delphi encrypt
	cli.Run()

	assert.Contains(t, buf.String(), "DELPHI ENCRYPTED MESSAGE")

	// pem from bytes
	pem, _ := pem.Decode(buf.Bytes())
	assert.NotNil(t, pem)

	// msg from pem
	msg := new(delphi.Message)
	err = msg.FromPEM(*pem)
	assert.NoError(t, err)

	assert.Equal(t, "falling-grass", msg.RecipientKey.Nickname())
	assert.Equal(t, "bitter-frost", msg.SenderKey.Nickname())

}
