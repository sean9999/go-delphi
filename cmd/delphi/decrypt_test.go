package main

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/sean9999/go-delphi"
	"github.com/sean9999/hermeti"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
)

func TestDecrypt(t *testing.T) {

	//	cli with testing env
	app := new(delphiApp)
	cli := hermeti.NewTestCli(app)
	cli.Env.Args = []string{"delphi", "decrypt"}
	cli.Env.Randomness = rand.Reader

	//	capture output
	buf := new(bytes.Buffer)
	cli.Env.OutStream = buf

	//	mount ../../testdata into memory-backed fs
	subfs := afero.NewIOFS(afero.NewBasePathFs(afero.NewOsFs(), "../../testdata"))
	cli.Env.Mount(subfs, "./testdata")

	//	pipe in priv key and message
	cli.Env.PipeInFile("testdata/grass-to-frost.pem")
	cli.Env.PipeInFile("testdata/bitter-frost.pem")

	app.Init(cli.Env)
	cli.Run()

	//	convert output back into Message
	msg := new(delphi.Message)
	i, _ := msg.Write(buf.Bytes())
	assert.Greater(t, i, 0)

	assert.Contains(t, string(msg.PlainText), "Callimachus")
	assert.Equal(t, msg.RecipientKey.Nickname(), "bitter-frost")
	assert.Equal(t, msg.SenderKey.Nickname(), "falling-grass")
	assert.NotNil(t, msg.Nonce)
	assert.NotNil(t, msg.Eph)

}
