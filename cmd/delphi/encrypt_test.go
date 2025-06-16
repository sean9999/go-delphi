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

func TestEncrypt(t *testing.T) {

	//	cli with testing env
	app := new(DelphiApp)
	cli := hermeti.NewTestCli(app)
	cli.Env.Args = []string{"delphi", "encrypt"}
	cli.Env.Randomness = rand.Reader

	//	mount ../../testdata into memory-backed fs
	subfs := afero.NewIOFS(afero.NewBasePathFs(afero.NewOsFs(), "../../testdata"))
	cli.Env.Mount(subfs, "./testdata")

	//	encrypt needs:
	// 		1. a private key (the principal doing the encrypting)
	//		2. something to encrypt (a plain message)
	//		3. a public key (who are we encrypting to?)
	err := cli.Env.PipeInFiles("testdata/falling-grass.pub.pem", "testdata/bitter-frost.pem", "testdata/fortune_feynman.pem")
	if err != nil {
		t.Fatal(err)
	}

	//	run cat testdata/those_3_pems.pem | delphi encrypt
	cli.Run()
	buf, _ := cli.OutStream()
	assert.Contains(t, buf.String(), "DELPHI ENCRYPTED MESSAGE")

	// pem from bytes
	pem, _ := pem.Decode(buf.Bytes())
	assert.NotNil(t, pem)

	// msg from pem
	msg := new(delphi.Message)
	err = msg.FromPEM(*pem)
	assert.NoError(t, err)

	assert.False(t, delphi.Nonce.IsZero(msg.Nonce))

	assert.Len(t, msg.Eph, delphi.KeySize)

	assert.Equal(t, "falling-grass", msg.RecipientKey.Nickname())
	assert.Equal(t, "bitter-frost", msg.SenderKey.Nickname())

}
