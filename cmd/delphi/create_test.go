package main

import (
	"crypto/rand"
	"io"
	"testing"

	"github.com/sean9999/go-delphi"
	"github.com/sean9999/hermeti"
	"github.com/stretchr/testify/assert"
)

// deterministicRand is a deterministic source of randomness.
// In other words, not random at all.
type deterministicRand struct{}

func (dr deterministicRand) Read(bs []byte) (int, error) {
	if bs == nil {
		return 0, io.EOF
	}
	for i := range bs {
		bs[i] = 1
	}
	return len(bs), nil
}

func TestCreate(t *testing.T) {

	app := new(DelphiApp)
	cli := hermeti.NewTestCli(app)
	cli.Env.Randomness = deterministicRand{}
	cli.Env.Args = []string{"delphi", "create"}
	cli.Run()

	output, err := cli.OutStream()
	if err != nil {
		t.Error(err)
	}

	msg := new(delphi.Message)
	_, err = io.Copy(msg, output)
	assert.ErrorIs(t, err, io.EOF)

	assert.Equal(t, delphi.Subject("DELPHI PRIVATE KEY"), msg.Subject)
	assert.Equal(t, "falling-dawn", msg.Headers.Get(delphi.Keyspace, "nick"))

}

func BenchmarkCreate(b *testing.B) {

	app := new(delphiApp)
	cli := hermeti.NewTestCli(app)
	cli.Env.Randomness = rand.Reader
	cli.Env.Args = []string{"delphi", "create"}

	for b.Loop() {
		cli.Run()
	}

}
