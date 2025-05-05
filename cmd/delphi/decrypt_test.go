package main

import (
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

	//	mount ../../testdata into memory-backed fs
	subfs := afero.NewIOFS(afero.NewBasePathFs(afero.NewOsFs(), "../../testdata"))
	cli.Env.Mount(subfs, "./testdata")

	//	pipe in priv key and message
	cli.Env.PipeInFile("testdata/falling-grass.pem")
	cli.Env.PipeInFile("testdata/message.cypher.pem")

	cli.Run()

	buf, err := cli.OutStream()
	assert.NoError(t, err)

	//	convert output back into Message
	msg := new(delphi.Message)

	if buf.Len() == 0 {
		assert.Fail(t, "nil output buffer")
	}

	i, _ := msg.Write(buf.Bytes())
	assert.Greater(t, i, 0)

	assert.Contains(t, string(msg.PlainText), "GNP growth projections")
	assert.Equal(t, msg.RecipientKey.Nickname(), "falling-grass")
	assert.Equal(t, msg.SenderKey.Nickname(), "bitter-frost")
	assert.NotNil(t, msg.Nonce)
	assert.NotNil(t, msg.Eph)

}
