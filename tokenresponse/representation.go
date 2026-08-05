package tokenresponse

type TokenResponseRepresentation struct {
	AccessToken     string   `json:"access_token,omitempty"`
	TokenType       string   `json:"token_type,omitempty"`
	ExpiresIn       int64    `json:"expires_in,omitempty"`
	RefreshToken    string   `json:"refresh_token,omitempty"`
	Scope           string   `json:"scope,omitempty"`
	IssuedTokenType string   `json:"issued_token_type,omitempty"`
	IdToken         string   `json:"id_token,omitempty"`
	Resources       []string `json:"resource,omitempty"`
}
