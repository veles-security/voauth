package velesoauth

import (
	"context"
	"crypto"

	"github.com/veles-security/vapi"
	velesapi "github.com/veles-security/vapi"
)

type JwtSigner struct {
	kid     string
	key     crypto.Signer
	alg     vapi.SigAlg
	encoder velesapi.EncodeSchemer[*Cliams, JwtClaimsEncoderOption]
}

func NewJwtSigner(key crypto.Signer, alg vapi.SigAlg, options ...JwtSignerPolicer) *JwtSigner {
	signer := &JwtSigner{
		key:     key,
		alg:     alg,
		encoder: &JwtClaimsEncoder{},
	}
	for _, option := range options {
		option(signer)
	}
	return signer
}

// Apply implements [JwtIssuerOption].
func (j *JwtSigner) Apply(ctx context.Context, token *JwtToken) error {
	signature, err := j.Sign(ctx, token)
	if err != nil {
		return err
	}
	token.signature = signature
	if j.kid != "" {
		token.header["kid"] = j.kid
	}
	return nil
}

// Sign implements [vapi.SignerSchemer].
func (j *JwtSigner) Sign(ctx context.Context, artifact *JwtToken, options ...JwtSignerPolicer) ([]byte, error) {
	config := *j
	for _, option := range options {
		option(&config)
	}

	claimsEncoded, err := config.encoder.Encode(ctx, &artifact.claims)
	if err != nil {
		return nil, err
	}
	signer := vapi.Signer{
		Key: config.key,
		Alg: config.alg,
	}
	signature, err := signer.Sign(ctx, vapi.Message(claimsEncoded))
	if err != nil {
		return nil, err
	}

	return signature, nil
}

// ----------------------------------------------------------------------------

type JwtSignerPolicer func(*JwtSigner)

func WithKid(kid string) JwtSignerPolicer {
	return func(j *JwtSigner) {
		j.kid = kid
	}
}

func WithKey(key crypto.Signer) JwtSignerPolicer {
	return func(j *JwtSigner) {
		j.key = key
	}
}

func WithAlg(alg vapi.SigAlg) JwtSignerPolicer {
	return func(j *JwtSigner) {
		j.alg = alg
	}
}

// ----------------------------------------------------------------------------

var _ vapi.SignerSchemer[*JwtToken, JwtSignerPolicer] = &JwtSigner{}
var _ JwtIssuerOption = &JwtSigner{}
