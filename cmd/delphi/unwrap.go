package main

import (
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/sean9999/hermeti"
)

func (a *appstate) unwrap(env hermeti.Env) {

	if len(a.pems) == 0 {
		fmt.Fprintln(env.ErrStream, errors.New("no pems"))
		return
	}

	for subj, pems := range a.pems {
		fmt.Fprintln(env.OutStream, subj)
		for _, pem := range pems {
			var dst []byte
			_, err := base64.StdEncoding.Decode(dst, pem.Bytes)
			if err != nil {
				fmt.Fprintln(env.ErrStream, err)
			} else {
				fmt.Fprintln(env.OutStream, string(dst))
			}
		}
	}

}
