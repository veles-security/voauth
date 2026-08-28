package jwt

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/veles-security/vapi"
	"github.com/veles-security/vcrypt/jws"
)

type Issuer struct {
	signer         vapi.Signer[jws.SignerOption, jws.JWS]
	runtimeOptions []IssuerOption
}

type IssuerConfigOption func(*Issuer) error

type IssueFunc func(ctx context.Context, token *Token) error

type IssuerOption func(next IssueFunc) IssueFunc

func NewIssuer(configOptions ...IssuerConfigOption) (*Issuer, error) {
	issuer := &Issuer{}
	for _, option := range configOptions {
		if option == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("nil issuer config option"))
		}
		if err := option(issuer); err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, err)
		}
	}
	return issuer, nil
}

// Issue implements [vapi.Issuer].
func (j *Issuer) Issue(ctx context.Context, options ...IssuerOption) (*Token, error) {
	if j == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("cannot issue JWT with nil issuer"))
	}
	token := &Token{iat: time.Now(), Header: map[string]string{}, Claims: make(Cliams)}

	allOptions := make([]IssuerOption, 0, len(j.runtimeOptions)+len(options))
	allOptions = append(allOptions, j.runtimeOptions...)
	allOptions = append(allOptions, options...)

	next := j.issue
	for index := len(allOptions) - 1; index >= 0; index-- {
		option := allOptions[index]
		if option == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("nil issuer option at index %d", index))
		}
		next = option(next)
		if next == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("issuer option at index %d returned nil IssueFunc", index))
		}
	}
	if err := next(ctx, token); err != nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("issue JWT: %w", err))
	}
	return token, nil
}

func (j *Issuer) issue(ctx context.Context, token *Token) error {
	jti, err := j.JTI(16)
	if err != nil {
		return fmt.Errorf("generate JWT ID: %w", err)
	}
	token.Claims["iat"] = token.iat.Unix()
	token.Claims["jti"] = jti

	if j.signer == nil {
		token.Header["alg"] = "none"
		token.signature = nil
		return nil
	}

	claims, err := json.Marshal(token.Claims)
	if err != nil {
		return vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("encode JWT claims for signing: %w", err))
	}

	jws, err := j.signer.Sign(ctx, claims)
	if err != nil {
		return vapi.NewErrorCategory(vapi.ErrInternal, fmt.Errorf("sign failed: %w", err))
	}
	token.signature = jws.Signature

	if err := json.Unmarshal(jws.Header, &token.Header); err != nil {
		return vapi.NewErrorCategory(vapi.ErrInternal, fmt.Errorf("header unmarshal failed: %w", err))
	}

	return nil
}

func (j *Issuer) IssueForPrincipal(ctx context.Context, principal vapi.Principal) (*Token, error) {
	return j.Issue(ctx, WithPrincipal(principal))
}

func (j *Issuer) JTI(nbytes int) (string, error) {
	b := make([]byte, nbytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

var _ vapi.Issuer[IssuerOption, *Token] = &Issuer{}
var _ vapi.PrincipalIssuer[IssuerOption, *Token] = &Issuer{}
