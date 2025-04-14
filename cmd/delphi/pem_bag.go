package main

import (
	"encoding/pem"

	"github.com/sean9999/go-delphi"
)

type pemBag map[delphi.Subject][]pem.Block

func (p *pemBag) Has(subject delphi.Subject) bool {
	bag := *p
	blocks, ok := bag[subject]
	if !ok {
		return false
	}
	if len(blocks) == 0 {
		return false
	}
	return true
}

func (p *pemBag) Pluck(subject delphi.Subject) *pem.Block {
	bag := *p
	blocks, ok := bag[subject]
	if !ok {
		return nil
	}
	if len(blocks) == 0 {
		return nil
	}
	if len(blocks) == 0 {
		return nil
	}
	priv := blocks[0]
	bag[subject] = bag[subject][1:]
	return &priv
}
