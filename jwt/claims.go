package jwt

const (
	TokenClaimsKind = "oauth2:token:claims" // #nosec G101 -- token kind identifier, not a credential
)

type Cliams map[string]any

// Kind implements [velesapi.Artifacter].
func (j *Cliams) Kind() string {
	return TokenClaimsKind
}
