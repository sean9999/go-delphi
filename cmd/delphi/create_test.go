package main

import (
	"encoding/pem"
	"io"
	"testing"

	"github.com/sean9999/go-delphi"
	"github.com/sean9999/hermeti"
	"github.com/stretchr/testify/assert"
)

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
	state := new(delphiApp)
	cli := hermeti.NewTestCli[*delphiApp](state)

	cli.Env.Randomness = deterministicRand{}

	cli.Env.Args = []string{"delphi", "create"}
	state.Init(cli.Env)
	cli.Run()

	output, err := io.ReadAll(cli.Env.OutStream.(io.Reader))
	if err != nil {
		t.Error(err)
	}

	msg := new(delphi.Message)
	p, _ := pem.Decode(output)

	err = msg.FromPEM(*p)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, "DELPHI PRIVATE KEY", p.Type)
	assert.Equal(t, "falling-dawn", msg.Headers.Get(delphi.Keyspace, "nick"))

}
