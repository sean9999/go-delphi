package main

import (
	"errors"

	"github.com/sean9999/go-delphi"
)

var ErrNoPrivKey = errors.New("no private key")

func (a *appstate) pluckPriv() bool {
	selfPem := a.pems.Pluck(delphi.Privkey)
	if selfPem == nil {
		return false
	}

	self := new(delphi.Principal)
	err := self.UnmarshalPEM(*selfPem)
	if err != nil {
		return false
	}
	a.self = *self
	return true
}

var ErrNoRecipient = errors.New("no recipient")

// TODO: catch when more than one priv key is sent in
// func pluckPriv(theRest pemList) (*pem.Block, pemList) {
// 	the1Pem := new(pem.Block)
// 	count := 0

// 	if theRest.has("DELPHI PRIVATE KEY") {
// 		newList, err := theRest.pluck("DELPHI PRIVATE KEY")

// 	}

// 	// theRest = slices.DeleteFunc(theRest, func(pb pem.Block) bool {
// 	// 	if pb.Type == {
// 	// 		count++
// 	// 		the1Pem = &pb
// 	// 		return true
// 	// 	}
// 	// 	return false
// 	// })

// 	if count > 1 {
// 		panic("you passed in more than one private key")
// 	}

// 	return the1Pem, theRest
// }
