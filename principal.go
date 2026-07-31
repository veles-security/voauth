package voauth

import (
	"context"
	"errors"
	"strings"
	"time"

	velesapi "github.com/veles-security/vapi"
)

type JwtPrincipalExtractor struct {
	Mappers []JwtPrincipalMapper
}

// ExtractPrincipal implements [velesapi.PrincipalSchemer].
func (j *JwtPrincipalExtractor) ExtractPrincipal(ctx context.Context, token *JwtToken, mappers ...JwtPrincipalMapper) (velesapi.Principaler, error) {
	issuer, ok := token.Claims["iss"].(string)
	if !ok {
		issuer = ""
	}
	subject, ok := token.Claims["sub"].(string)
	if !ok {
		subject = ""
	}

	p := velesapi.NewBasePrincipal(issuer, subject, "oauth2:principal")

	mapp := func(mappers []JwtPrincipalMapper) error {
		for _, mapper := range mappers {
			if err := mapper.Map(token, p); err != nil {
				return err
			}
		}
		return nil
	}

	if err := mapp(j.Mappers); err != nil {
		return nil, err
	}
	if err := mapp(mappers); err != nil {
		return nil, err
	}

	return p, nil
}

type JwtPrincipalMapper interface {
	Map(token *JwtToken, principal velesapi.Principaler) error
}

type JwtPrincipalMapperFunc func(token *JwtToken, principal velesapi.Principaler) error

func (f JwtPrincipalMapperFunc) Map(token *JwtToken, principal velesapi.Principaler) error {
	return f(token, principal)
}

// JwtStandardClaimsMapper maps the commonly used JWT and OpenID Connect claims.
// AssuranceLevels optionally translates acr values into application assurance levels.
type JwtStandardClaimsMapper struct {
	Source          string
	AssuranceLevels map[string]int
}

func (m JwtStandardClaimsMapper) Map(token *JwtToken, principal velesapi.Principaler) error {
	p, ok := principal.(*velesapi.Principal)
	if !ok {
		return errors.New("voauth: standard claims mapper requires *velesapi.Principal")
	}

	p.WithClaims(token.Claims)
	if value, ok := token.Claims["name"].(string); ok {
		p.WithDisplayName(value)
	}
	if value, ok := token.Claims["preferred_username"].(string); ok {
		p.WithUsername(value)
	}
	if value, ok := token.Claims["email"].(string); ok {
		p.WithEmail(value)
	}
	if value, ok := m.numericDate(token.Claims["iat"]); ok {
		p.WithIssuedAt(value)
	}
	if value, ok := m.numericDate(token.Claims["auth_time"]); ok {
		p.WithAuthenticatedAt(value)
	}

	acr, _ := token.Claims["acr"].(string)
	assurance := m.AssuranceLevels[acr]
	p.WithAuthentication(m.authenticationMethods(token.Claims["amr"]), acr, assurance)
	source := m.Source
	if source == "" {
		source = "oauth2:jwt"
	}
	p.WithSource(source)
	return nil
}

func (m JwtStandardClaimsMapper) authenticationMethods(value any) string {
	switch methods := value.(type) {
	case string:
		return methods
	case []any:
		values := make([]string, 0, len(methods))
		for _, method := range methods {
			if method, ok := method.(string); ok {
				values = append(values, method)
			}
		}
		return strings.Join(values, " ")
	case []string:
		return strings.Join(methods, " ")
	default:
		return ""
	}
}

func (m JwtStandardClaimsMapper) numericDate(value any) (time.Time, bool) {
	seconds, ok := value.(float64)
	if !ok {
		return time.Time{}, false
	}
	whole := int64(seconds)
	nanos := int64((seconds - float64(whole)) * 1e9)
	return time.Unix(whole, nanos).UTC(), true
}

// JwtAttributesMapper copies selected claims into principal attributes. An empty
// Claims slice copies all claims.
type JwtAttributesMapper struct {
	Claims []string
}

func (m JwtAttributesMapper) Map(token *JwtToken, principal velesapi.Principaler) error {
	p, ok := principal.(*velesapi.Principal)
	if !ok {
		return errors.New("voauth: attributes mapper requires *velesapi.Principal")
	}
	if len(m.Claims) == 0 {
		p.WithAttributes(token.Claims)
		return nil
	}
	attributes := make(map[string]any, len(m.Claims))
	for _, name := range m.Claims {
		if value, ok := token.Claims[name]; ok {
			attributes[name] = value
		}
	}
	p.WithAttributes(attributes)
	return nil
}

var _ velesapi.PrincipalSchemer[*JwtToken, JwtPrincipalMapper] = &JwtPrincipalExtractor{}
var _ JwtPrincipalMapper = JwtPrincipalMapperFunc(nil)
var _ JwtPrincipalMapper = JwtStandardClaimsMapper{}
var _ JwtPrincipalMapper = JwtAttributesMapper{}
