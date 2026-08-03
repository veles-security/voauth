package voauth

type Token interface {
	Kind() string
	TokenType() string
}
