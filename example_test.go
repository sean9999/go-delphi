package delphi_test

import (
	"crypto/rand"
	"fmt"
	"slices"
	"testing"

	"github.com/sean9999/go-delphi"
	"github.com/stretchr/testify/assert"
)

func TestExample(t *testing.T) {

	//	some plain text
	sentence := []byte("hello world")

	//	create two principals
	alice := delphi.NewPrincipal(rand.Reader)
	bob := delphi.NewPrincipal(rand.Reader)

	//	create a message for bob, from alice
	msg := delphi.ComposeMessage(rand.Reader, delphi.PlainMessage, sentence)
	msg.SenderKey = alice.PublicKey()

	//	add some metadata (this becomes AAD)
	msg.Headers["foo"] = "bar"
	msg.Headers["bing"] = "bat"

	//	encrypt message
	err := msg.Encrypt(rand.Reader, alice, bob.PublicKey(), nil)
	assert.NoError(t, err)

	//	decrpyt message
	err = bob.Decrypt(msg, nil)
	assert.NoError(t, err)

	//	is decrypted text same as plain text?
	assert.Equal(t, sentence, msg.PlainText)

	//	has the metadata survived?
	foo, ok := msg.Headers["foo"]
	assert.True(t, ok)
	assert.Equal(t, "bar", foo)

}

func Example() {

	//	some plain text
	sentence := []byte("hello world")

	//	create two principals
	alice := delphi.NewPrincipal(rand.Reader)
	bob := delphi.NewPrincipal(rand.Reader)

	//	create a message for bob, from alice
	msg := delphi.ComposeMessage(rand.Reader, delphi.PlainMessage, sentence)
	msg.SenderKey = alice.PublicKey()

	//	add some metadata (this becomes AAD)
	msg.Headers["foo"] = "bar"
	msg.Headers["bing"] = "bat"

	//	encrypt message
	err := msg.Encrypt(rand.Reader, alice, bob.PublicKey(), nil)
	fmt.Println("should be nil", err)

	//	decrpyt message
	err = bob.Decrypt(msg, nil)
	fmt.Println("should be nil", err)

	//	is decrypted text same as plain text?
	diff := slices.Compare(sentence, msg.PlainText)
	fmt.Println("should be 0", diff)

	//	has the metadata survived?
	foo, ok := msg.Headers["foo"]

	fmt.Println("should be true", ok)
	fmt.Println(foo)
	// Output:
	// should be nil <nil>
	// should be nil <nil>
	// should be 0 0
	// should be true true
	// bar

}

func multi(nums []int) int {
	result := 1
	for _, n := range nums {
		result = result * n
	}
	return result
}
