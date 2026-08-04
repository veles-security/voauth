package token

type AnyToken interface {
	Kind() string
	TokenType() string
}
