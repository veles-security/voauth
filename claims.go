package voauth

const (
	TokenClaimsKind = "oauth2:token:claims"
)

type Cliams map[string]any

// Kind implements [velesapi.Artifacter].
func (j *Cliams) Kind() string {
	return TokenClaimsKind
}
