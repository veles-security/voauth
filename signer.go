package voauth

import (
	"context"
	"crypto"

	"github.com/veles-security/vapi"
	"github.com/veles-security/vapi/sig"
)

type JwtSigner struct {
	kid     string
	key     crypto.Signer
	alg     sig.SigAlg
	encoder vapi.Encoder[*Cliams, JwtClaimsEncoderOption]
}

func NewJwtSigner(key crypto.Signer, alg sig.SigAlg, options ...JwtSignerPolicer) *JwtSigner {
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

// ApplyIssuerOption implements [JwtIssuerOption].
func (j *JwtSigner) ApplyIssuerOption(ctx context.Context, token *JwtToken) error {
	signature, err := j.Sign(ctx, token)
	if err != nil {
		return err
	}
	token.signature = signature
	if j.kid != "" {
		token.Header["kid"] = j.kid
	}
	alg, err := j.alg.ToOAuth()
	if err != nil {
		return err
	}
	token.Header["alg"] = alg
	return nil
}

// Sign implements [vapi.SignerSchemer].
func (j *JwtSigner) Sign(ctx context.Context, artifact *JwtToken, options ...JwtSignerPolicer) ([]byte, error) {
	config := *j
	for _, option := range options {
		option(&config)
	}

	claimsEncoded, err := config.encoder.Encode(ctx, &artifact.Claims)
	if err != nil {
		return nil, err
	}
	signer := sig.Signer{
		Key: config.key,
		Alg: config.alg,
	}
	signature, err := signer.Sign(ctx, sig.Message(claimsEncoded))
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

func WithAlg(alg sig.SigAlg) JwtSignerPolicer {
	return func(j *JwtSigner) {
		j.alg = alg
	}
}

// ----------------------------------------------------------------------------

var _ vapi.Signer[*JwtToken, JwtSignerPolicer] = &JwtSigner{}
var _ JwtIssuerOption = &JwtSigner{}
