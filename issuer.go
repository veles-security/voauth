package velesoauth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	velesapi "github.com/veles-security/vapi"
)

type JwtIssuer struct {
	Options []JwtIssuerOption
}

// Issue implements [velesapi.IssueSchemer].
func (j *JwtIssuer) Issue(ctx context.Context, options ...JwtIssuerOption) (*JwtToken, error) {
	token := &JwtToken{}

	applyOptions := func(ps []JwtIssuerOption) error {
		for _, p := range ps {
			err := p.Apply(ctx, token)
			if err != nil {
				return err
			}
		}
		return nil
	}

	if err := applyOptions(j.Options); err != nil {
		return nil, err
	}
	if err := applyOptions(options); err != nil {
		return nil, err
	}

	return token, nil
}

type JwtIssuerOption interface {
	Apply(ctx context.Context, token *JwtToken) error
}

type JwtIssuerOptionFunc func(ctx context.Context, token *JwtToken) error

func (f JwtIssuerOptionFunc) Apply(ctx context.Context, token *JwtToken) error {
	return f(ctx, token)
}

func WithJwtSignature(kid, alg string, key crypto.PrivateKey) JwtIssuerOption {
	return JwtIssuerOptionFunc(func(_ context.Context, token *JwtToken) error {
		if token == nil || alg == "" || key == nil {
			return velesapi.NewErrorCategory(velesapi.ErrPolicyRejected, errors.New("incomplete JWT signature configuration"))
		}

		if token.header == nil {
			token.header = make(map[string]string, 2)
		}
		token.header["alg"] = alg
		if kid != "" {
			token.header["kid"] = kid
		} else {
			delete(token.header, "kid")
		}
		if token.claims == nil {
			token.claims = make(map[string]any)
		}

		header, err := json.Marshal(token.header)
		if err != nil {
			return err
		}
		claims, err := json.Marshal(token.claims)
		if err != nil {
			return err
		}
		headerLen := base64.RawURLEncoding.EncodedLen(len(header))
		claimsLen := base64.RawURLEncoding.EncodedLen(len(claims))
		signingInput := make([]byte, headerLen+1+claimsLen)
		base64.RawURLEncoding.Encode(signingInput[:headerLen], header)
		signingInput[headerLen] = '.'
		base64.RawURLEncoding.Encode(signingInput[headerLen+1:], claims)

		var hash crypto.Hash
		switch alg {
		case "RS256", "PS256", "ES256":
			hash = crypto.SHA256
		case "RS384", "PS384", "ES384":
			hash = crypto.SHA384
		case "RS512", "PS512", "ES512":
			hash = crypto.SHA512
		case "EdDSA":
			edKey, ok := key.(ed25519.PrivateKey)
			if !ok {
				return velesapi.NewErrorCategory(velesapi.ErrPolicyRejected, fmt.Errorf("invalid private key for %s", alg))
			}
			token.signature = ed25519.Sign(edKey, signingInput)
		default:
			return velesapi.NewErrorCategory(velesapi.ErrUnsupported, fmt.Errorf("unsupported JWT signature algorithm %q", alg))
		}

		if alg != "EdDSA" {
			hasher := hash.New()
			_, _ = hasher.Write(signingInput)
			digest := hasher.Sum(nil)
			switch {
			case alg[:2] == "RS":
				rsaKey, ok := key.(*rsa.PrivateKey)
				if !ok {
					return velesapi.NewErrorCategory(velesapi.ErrPolicyRejected, fmt.Errorf("invalid private key for %s", alg))
				}
				token.signature, err = rsa.SignPKCS1v15(rand.Reader, rsaKey, hash, digest)
			case alg[:2] == "PS":
				rsaKey, ok := key.(*rsa.PrivateKey)
				if !ok {
					return velesapi.NewErrorCategory(velesapi.ErrPolicyRejected, fmt.Errorf("invalid private key for %s", alg))
				}
				token.signature, err = rsa.SignPSS(rand.Reader, rsaKey, hash, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
			case alg[:2] == "ES":
				ecdsaKey, ok := key.(*ecdsa.PrivateKey)
				if !ok {
					return velesapi.NewErrorCategory(velesapi.ErrPolicyRejected, fmt.Errorf("invalid private key for %s", alg))
				}
				r, s, signErr := ecdsa.Sign(rand.Reader, ecdsaKey, digest)
				if signErr != nil {
					err = signErr
					break
				}
				size := (ecdsaKey.Curve.Params().BitSize + 7) / 8
				token.signature = make([]byte, size*2)
				r.FillBytes(token.signature[:size])
				s.FillBytes(token.signature[size:])
			}
			if err != nil {
				return err
			}
		}

		token.headerRaw = append(token.headerRaw[:0], signingInput[:headerLen]...)
		token.claimsRaw = append(token.claimsRaw[:0], signingInput[headerLen+1:]...)
		signatureLen := base64.RawURLEncoding.EncodedLen(len(token.signature))
		token.raw = make([]byte, len(signingInput)+1+signatureLen)
		copy(token.raw, signingInput)
		token.raw[len(signingInput)] = '.'
		base64.RawURLEncoding.Encode(token.raw[len(signingInput)+1:], token.signature)
		token.signature = token.raw[len(signingInput)+1:]
		return nil
	})
}

func WithJwtIssuer(issuer string) JwtIssuerOption {
	return JwtIssuerOptionFunc(func(_ context.Context, token *JwtToken) error {
		if token.claims == nil {
			token.claims = make(map[string]any)
		}
		token.claims["iss"] = issuer
		return nil
	})
}

func WithJwtPrincipal(principal velesapi.Principaler) JwtIssuerOption {
	return JwtIssuerOptionFunc(func(_ context.Context, token *JwtToken) error {
		if principal == nil {
			return velesapi.NewErrorCategory(velesapi.ErrPolicyRejected, errors.New("nil principal"))
		}
		if token.claims == nil {
			token.claims = make(map[string]any)
		}
		for name, value := range principal.Claims() {
			token.claims[name] = value
		}
		token.claims["iss"] = principal.Issuer()
		token.claims["sub"] = principal.Subject()
		return nil
	})
}

var _ velesapi.IssueSchemer[JwtIssuerOption, *JwtToken] = &JwtIssuer{}
var _ JwtIssuerOption = JwtIssuerOptionFunc(nil)
