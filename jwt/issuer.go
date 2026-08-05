package jwt

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"time"

	"github.com/veles-security/vapi"
	"github.com/veles-security/vapi/sig"
)

type Issuer struct {
	signer  *sig.Signer
	options []JwtIssuerOption
}

func NewIssuer(signer *sig.Signer, options ...JwtIssuerOption) *Issuer {
	issuer := &Issuer{signer: signer}
	issuer.options = options
	return issuer
}

// Issue implements [vapi.IssueSchemer].
func (j *Issuer) Issue(ctx context.Context, options ...JwtIssuerOption) (*Token, error) {
	if j == nil || j.signer == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("cannot issue JWT with nil signer"))
	}
	token := &Token{
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

	token.Claims["iat"] = token.iat.Unix()
	token.Claims["jti"] = jti

	algorithm, err := j.signer.Alg.ToOAuth()
	if err != nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("encode JWT signing algorithm: %w", err))
	}
	token.Header["alg"] = algorithm
	if j.signer.Kid != "" {
		token.Header["kid"] = j.signer.Kid
	}

	header, err := json.Marshal(token.Header)
	if err != nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("encode JWT header for signing: %w", err))
	}
	claims, err := json.Marshal(token.Claims)
	if err != nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("encode JWT claims for signing: %w", err))
	}
	headerEncoded := base64.RawURLEncoding.EncodeToString(header)
	claimsEncoded := base64.RawURLEncoding.EncodeToString(claims)
	signingInput := []byte(headerEncoded + "." + claimsEncoded)
	token.signature, err = j.signer.Sign(ctx, sig.Message(signingInput))
	if err != nil {
		return nil, fmt.Errorf("sign JWT: %w", err)
	}

	return token, nil
}

// IssueForPrincipal implements [vapi.IssueForPrincipalSchemer].
func (j *Issuer) IssueForPrincipal(ctx context.Context, principal vapi.Principal) (*Token, error) {
	return nil, nil
}

func (j *Issuer) JTI(nbytes int) (string, error) {
	b := make([]byte, nbytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

type JwtIssuerOption interface {
	ApplyIssuerOption(ctx context.Context, token *Token) error
}

type JwtIssuerOptionFunc func(ctx context.Context, token *Token) error

func (f JwtIssuerOptionFunc) ApplyIssuerOption(ctx context.Context, token *Token) error {
	return f(ctx, token)
}

func WithSubject(subject string) JwtIssuerOption {
	return JwtIssuerOptionFunc(func(_ context.Context, token *Token) error {
		if token.Claims == nil {
			token.Claims = make(map[string]any)
		}
		token.Claims["sub"] = subject
		return nil
	})
}

func WithIssuer(issuer string) JwtIssuerOption {
	return JwtIssuerOptionFunc(func(_ context.Context, token *Token) error {
		if token.Claims == nil {
			token.Claims = make(map[string]any)
		}
		token.Claims["iss"] = issuer
		return nil
	})
}

func WithExp(exp time.Duration) JwtIssuerOption {
	return JwtIssuerOptionFunc(func(_ context.Context, token *Token) error {
		if token.Claims == nil {
			token.Claims = make(map[string]any)
		}
		token.Claims["exp"] = token.iat.Add(exp).Unix()
		return nil
	})
}

func WithClaims(cliams Cliams) JwtIssuerOption {
	return JwtIssuerOptionFunc(func(_ context.Context, token *Token) error {
		if token.Claims == nil {
			token.Claims = make(map[string]any)
		}
		maps.Copy(token.Claims, cliams)
		return nil
	})
}

func WithPrincipal(principal vapi.Principal) JwtIssuerOption {
	return JwtIssuerOptionFunc(func(_ context.Context, token *Token) error {
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

var _ vapi.Issuer[JwtIssuerOption, *Token] = &Issuer{}
var _ vapi.PrincipalIssuer[JwtIssuerOption, *Token] = &Issuer{}
var _ JwtIssuerOption = JwtIssuerOptionFunc(nil)
