package delphi

import "strings"

type Subject string

func (subj Subject) Equals(str string) bool {
	a := strings.ToUpper(string(subj))
	b := strings.ToUpper(str)
	return (a == b)
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
