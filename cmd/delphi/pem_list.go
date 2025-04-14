package main

import (
	"encoding/pem"
	"slices"

	"github.com/sean9999/go-delphi"
	"github.com/sean9999/hermeti/fmt"
)

type pemList []pem.Block

func (pl pemList) index(typ delphi.Subject) int {
	for i, p := range pl {
		if p.Type == string(typ) {
			return i
		}
	}
	return -1
}

func (pl pemList) has(typ delphi.Subject) bool {
	i := pl.index(typ)
	return i >= 0
}

// func (pl pemList) count(typ string) int {
// 	n := 0
// 	for _, p := range pl {
// 		if p.Type == typ {
// 			n++
// 		}
// 	}
// 	return n
// }

func (pl pemList) pluck(typ delphi.Subject) (pemList, *pem.Block, error) {
	var shortList pemList
	var block *pem.Block
	if i := pl.index(typ); i >= 0 {
		shortList = slices.Delete(pl, i, i+1)
		block = &pl[i]
	} else {
		return shortList, nil, fmt.Errorf("no pem of type %q found", typ)
	}
	return shortList, block, nil
}
