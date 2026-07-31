package voauth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"maps"
	"time"

	"github.com/veles-security/vapi"
)

type JwtIssuer struct {
	options []JwtIssuerOption
}

func NewJwtIssuer(options ...JwtIssuerOption) *JwtIssuer {
	issuer := &JwtIssuer{}
	issuer.options = options
	return issuer
}

// Issue implements [vapi.IssueSchemer].
func (j *JwtIssuer) Issue(ctx context.Context, options ...JwtIssuerOption) (*JwtToken, error) {
	token := &JwtToken{
		iat:    time.Now(),
		Header: map[string]string{},
		Claims: make(Cliams),
	}

	applyOptions := func(ps []JwtIssuerOption) error {
		for _, p := range ps {
			err := p.ApplyIssuerOption(ctx, token)
			if err != nil {
				return err
			}
		}
		return nil
	}

	if err := applyOptions(j.options); err != nil {
		return nil, err
	}
	if err := applyOptions(options); err != nil {
		return nil, err
	}

	jti, err := j.JTI(16)
	if err != nil {
		return nil, err
	}

	token.Claims["iat"] = token.iat
	token.Claims["jti"] = jti

	return token, nil
}

// IssueForPrincipal implements [vapi.IssueForPrincipalSchemer].
func (j *JwtIssuer) IssueForPrincipal(ctx context.Context, principal vapi.Principal) (*JwtToken, error) {
	return nil, nil
}

func (j *JwtIssuer) JTI(nbytes int) (string, error) {
	b := make([]byte, nbytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

type JwtIssuerOption interface {
	ApplyIssuerOption(ctx context.Context, token *JwtToken) error
}

type JwtIssuerOptionFunc func(ctx context.Context, token *JwtToken) error

func (f JwtIssuerOptionFunc) ApplyIssuerOption(ctx context.Context, token *JwtToken) error {
	return f(ctx, token)
}

func WithSubject(subject string) JwtIssuerOption {
	return JwtIssuerOptionFunc(func(_ context.Context, token *JwtToken) error {
		if token.Claims == nil {
			token.Claims = make(map[string]any)
		}
		token.Claims["sub"] = subject
		return nil
	})
}

func WithIssuer(issuer string) JwtIssuerOption {
	return JwtIssuerOptionFunc(func(_ context.Context, token *JwtToken) error {
		if token.Claims == nil {
			token.Claims = make(map[string]any)
		}
		token.Claims["iss"] = issuer
		return nil
	})
}

func WithExp(exp time.Duration) JwtIssuerOption {
	return JwtIssuerOptionFunc(func(_ context.Context, token *JwtToken) error {
		if token.Claims == nil {
			token.Claims = make(map[string]any)
		}
		token.Claims["exp"] = token.iat.Add(exp).Unix()
		return nil
	})
}

func WithClaims(cliams Cliams) JwtIssuerOption {
	return JwtIssuerOptionFunc(func(_ context.Context, token *JwtToken) error {
		if token.Claims == nil {
			token.Claims = make(map[string]any)
		}
		maps.Copy(token.Claims, cliams)
		return nil
	})
}

func WithPrincipal(principal vapi.Principal) JwtIssuerOption {
	return JwtIssuerOptionFunc(func(_ context.Context, token *JwtToken) error {
		if principal == nil {
			return vapi.NewErrorCategory(vapi.ErrPolicyRejected, errors.New("nil principal"))
		}
		if token.Claims == nil {
			token.Claims = make(map[string]any)
		}
		for name, value := range principal.Claims() {
			token.Claims[name] = value
		}
		token.Claims["sub"] = principal.Subject()
		return nil
	})
}

var _ vapi.Issuer[JwtIssuerOption, *JwtToken] = &JwtIssuer{}
var _ vapi.PrincipalIssuer[JwtIssuerOption, *JwtToken] = &JwtIssuer{}
var _ JwtIssuerOption = JwtIssuerOptionFunc(nil)
