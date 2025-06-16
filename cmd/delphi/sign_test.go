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

func TestSign(t *testing.T) {

	//	cli with testing env
	app := new(DelphiApp)
	cli := hermeti.NewTestCli(app)
	cli.Env.Args = []string{"delphi", "sign"}
	cli.Env.Randomness = rand.Reader

	//	mount ../../testdata into memory-backed fs
	subFs := afero.NewIOFS(afero.NewBasePathFs(afero.NewOsFs(), "../../testdata"))
	cli.Env.Mount(subFs, "./testdata")

	//	Pipe recipient, self, and message into stdin. Recipient is not actually needed here and will be ignored
	err := cli.Env.PipeInFile("./testdata/stack.pem")
	if err != nil {
		t.Fatal(err)
	}

	//	run cat testdata/stack.p | delphi sign
	cli.Run()

	buf, _ := cli.OutStream()

	assert.Contains(t, buf.String(), "DELPHI PLAIN MESSAGE")

	// pem from bytes
	p, _ := pem.Decode(buf.Bytes())
	assert.NotNil(t, p)

	// msg from p
	msg := new(delphi.Message)
	err = msg.FromPEM(*p)
	assert.NoError(t, err)

	assert.Equal(t, "bitter-frost", msg.SenderKey.Nickname())
	assert.NotNil(t, msg.Sig)

}
