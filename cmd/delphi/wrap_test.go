package main

import (
	"crypto/rand"
	"testing"

	"github.com/sean9999/hermeti"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
)

func TestWrap(t *testing.T) {

	t.Run("with no randomness source", func(t *testing.T) {
		//	instantiate CLI in test mode
		app := new(DelphiApp)
		cli := hermeti.NewTestCli(app)
		cli.Env.Args = []string{"delphi", "wrap"}

		//	mount ./testdata/
		subfs := afero.NewIOFS(afero.NewBasePathFs(afero.NewOsFs(), "../../testdata"))
		cli.Env.Mount(subfs, "./testdata")
		cli.Env.PipeInFile("testdata/fortune.txt")

		cli.Run()

		buf, err := cli.OutStream()
		assert.NoError(t, err)

		//	it's all in the mind, you know. ( base64 encoded )
		body := "SXQncyBhbGwgaW4gdGhlIG1pbmQsIHlhIGtub3cuCg=="

		assert.Contains(t, buf.String(), "END DELPHI PLAIN MESSAGE")
		assert.Contains(t, buf.String(), body)

		//	there should not be a nonce
		assert.NotContains(t, buf.String(), "nonce")
	})

	t.Run("with a randomness source", func(t *testing.T) {
		//	instantiate CLI in test mode
		app := new(DelphiApp)
		cli := hermeti.NewTestCli(app)
		cli.Env.Args = []string{"delphi", "wrap"}
		cli.Env.Randomness = rand.Reader

		//	mount ./testdata/
		subfs := afero.NewIOFS(afero.NewBasePathFs(afero.NewOsFs(), "../../testdata"))
		cli.Env.Mount(subfs, "./testdata")
		cli.Env.PipeInFile("testdata/fortune.txt")

		cli.Run()

		buf, err := cli.OutStream()
		assert.NoError(t, err)

		//	it's all in the mind, you know. ( base64 encoded )
		body := "SXQncyBhbGwgaW4gdGhlIG1pbmQsIHlhIGtub3cuCg=="

		assert.Contains(t, buf.String(), "END DELPHI PLAIN MESSAGE")
		assert.Contains(t, buf.String(), body)

		//	we should have a nonce
		assert.Contains(t, buf.String(), "nonce")
	})

}
