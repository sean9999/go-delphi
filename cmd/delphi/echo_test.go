package main

import (
	"bytes"
	"fmt"
	"io"
	"testing"

	"github.com/sean9999/hermeti"
	"github.com/stretchr/testify/assert"
)

func TestEcho(t *testing.T) {

	app := new(delphiApp)
	cli := hermeti.NewTestCli(app)
	cli.Env.Args = []string{"delphi", "echo"}

	//	pipe in
	inBuf := bytes.NewBufferString(`
-----BEGIN DELPHI ASSERTION-----
delphi.v1/nonce: b93fbc55e278eb28576f34a0
delphi.v1/sender: 72fadf46107f706dd32f19b9c7867f19d70129e6bbb37c107c62e16021b34116c87595508bc5129297572e016ed823564ee5796fb03528cd15e976ab89e1f087
delphi.v1/sig: 4cf316760491ade9630ee468dd3fe6dccfcf96aa2ad445274f86fe607c0a3f266072c8226989d4b5e3ff18d589c74e4359ef9c0267942501ff20b00e9442b208

SSBhc3NlcnQgdGhhdCBJIGFtIG1lLg==
-----END DELPHI ASSERTION-----
	`)
	cli.Env.InStream = inBuf

	//	capture output
	outBuf := new(bytes.Buffer)
	cli.Env.OutStream = outBuf

	app.Init(cli.Env)
	cli.Run()

	o, err := cli.OutStream()
	if err != nil {
		fmt.Fprintln(cli.Env.ErrStream, err)
		return
	}

	output, err := io.ReadAll(o)
	if err != nil {
		fmt.Fprintln(cli.Env.ErrStream, err)
		return
	}

	assert.Contains(t, string(output), "I assert that I am me.")

}
