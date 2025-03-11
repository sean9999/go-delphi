package main

import (
	"flag"
	"fmt"
	"strings"

	"github.com/sean9999/go-delphi"
	"github.com/sean9999/hermeti"
)

// type appstate struct {
// 	self *delphi.User
// 	// Add other fields as needed
// }

func (a *appstate) encrypt(env hermeti.Env) {

	recipient := ""
	fset := flag.NewFlagSet("recipient", flag.ExitOnError)
	fset.StringVar(&recipient, "to", "", "recipient public key")
	fset.Parse(env.Args[2:])
	remainingArgs := fset.Args()

	if len(recipient) == 0 {
		fmt.Fprintln(env.ErrStream, "there must be a recipient")
		return
	}

	if len(remainingArgs) == 0 {
		fmt.Fprintln(env.ErrStream, "not enough args")
		return
	}

	body := strings.Join(remainingArgs, " ")
	msg := delphi.NewMessage(env.Randomness, []byte(body))
	msg.Recipient = delphi.KeyFromHex(recipient)
	msg.Sender = a.self.PublicKey()

	err := a.self.Encrypt(env.Randomness, msg, nil)
	if err != nil {
		fmt.Fprintln(env.ErrStream, err)
		return
	}
	fmt.Fprintln(env.OutStream, msg)
}
