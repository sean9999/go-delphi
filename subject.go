package delphi

import (
	"fmt"
	"strings"
)

type Subject string

// Equals returns true if any string-like value is the same as subj (case insensitive)
func (subj Subject) Equals(str any) bool {
	a := strings.ToUpper(string(subj))
	b := strings.ToUpper(fmt.Sprintf("%s", str))
	return a == b
}

func (subj Subject) String() string {
	return string(subj)
}

const (
	PlainMessage     Subject = "DELPHI PLAIN MESSAGE"
	EncryptedMessage Subject = "DELPHI ENCRYPTED MESSAGE"
	Assertion        Subject = "DELPHI ASSERTION"
	Pubkey           Subject = "DELPHI PUBLIC KEY"
	Privkey          Subject = "DELPHI PRIVATE KEY"
)
