// this does cool stuff
package main

import (
	"fmt"

	"github.com/sean9999/hermeti"
)

func main() {

	//	do something nice and useful with a panic
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("PANIC:", r)
		}
	}()

	app := new(DelphiApp)
	cli := hermeti.NewRealCli(app)
	cli.Run()

}
