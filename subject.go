package delphi

type Subject string

const (
	PlainMessage     Subject = "DELPHI PLAIN MESSAGE"
	EncryptedMessage Subject = "DELPHI ENCRYPTED MESSAGE"
	Assertion        Subject = "DELPHI ASSERTION"
	Pubkey           Subject = "DELPHI PUBLIC KEY"
	Privkey          Subject = "DELPHI PRIVATE KEY"
)
