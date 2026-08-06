package jwk

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/veles-security/vapi"
)

type Encoder struct {
	runtimeOptions []EncoderOption
}

type EncoderConfigOption func(*Encoder) error

// EncodeFunc populates a JWK representation. Encoder options decorate
// functions of this type.
type EncodeFunc func(context.Context, *Jwk, *JwkRepresentation) error

type EncoderOption func(next EncodeFunc) EncodeFunc

func NewEncoder(configOptions ...EncoderConfigOption) (*Encoder, error) {
	encoder := &Encoder{}
	for _, option := range configOptions {
		if option == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("nil encoder config option"))
		}
		if err := option(encoder); err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, err)
		}
	}
	return encoder, nil
}

// Encode implements [vapi.Encoder].
func (e *Encoder) Encode(ctx context.Context, artifact *Jwk, options ...EncoderOption) ([]byte, error) {
	if e == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("cannot encode JWK with nil encoder"))
	}
	if artifact == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("cannot encode nil JWK"))
	}
	if artifact.Key == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("cannot encode JWK with nil key"))
	}

	allOptions := make([]EncoderOption, 0, len(e.runtimeOptions)+len(options))
	allOptions = append(allOptions, e.runtimeOptions...)
	allOptions = append(allOptions, options...)

	next := e.encode
	for index := len(allOptions) - 1; index >= 0; index-- {
		option := allOptions[index]
		if option == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("nil encoder option at index %d", index))
		}
		wrapped := option(next)
		if wrapped == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("encoder option at index %d returned nil EncodeFunc", index))
		}
		next = wrapped
	}

	representation := &JwkRepresentation{}
	if err := next(ctx, artifact, representation); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(representation)
	if err != nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("encode JWK representation: %w", err))
	}
	return payload, nil
}

func (e *Encoder) encode(_ context.Context, artifact *Jwk, representation *JwkRepresentation) error {
	alg, err := artifact.Alg.ToOAuth()
	if err != nil {
		return vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("encode JWK algorithm: %w", err))
	}
	representation.Alg = alg
	representation.Kid = artifact.Kid

	switch key := artifact.Key.(type) {
	case []byte:
		representation.Kty = "oct"
		encoded := byteBuffer(base64.RawURLEncoding.EncodeToString(key))
		representation.K = &encoded
	case *rsa.PublicKey:
		representation.Kty = "RSA"
		n := byteBuffer(base64.RawURLEncoding.EncodeToString(key.N.Bytes()))
		representation.N = &n
		if key.E <= 0 {
			return vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("invalid RSA public exponent %d", key.E))
		}
		exponent := big.NewInt(int64(key.E)).Bytes()
		e := byteBuffer(base64.RawURLEncoding.EncodeToString(exponent))
		representation.E = &e
	case *ecdsa.PublicKey:
		representation.Kty = "EC"
		switch key.Curve.Params().Name {
		case "P-256":
			representation.Crv = "P-256"
		case "P-384":
			representation.Crv = "P-384"
		case "P-521":
			representation.Crv = "P-521"
		default:
			return vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("unsupported elliptic curve %q", key.Curve.Params().Name))
		}
		size := (key.Curve.Params().BitSize + 7) / 8
		x := make([]byte, size)
		y := make([]byte, size)
		key.X.FillBytes(x)
		key.Y.FillBytes(y)
		xEncoded := byteBuffer(base64.RawURLEncoding.EncodeToString(x))
		yEncoded := byteBuffer(base64.RawURLEncoding.EncodeToString(y))
		representation.X = &xEncoded
		representation.Y = &yEncoded
	case ed25519.PublicKey:
		representation.Kty = "OKP"
		representation.Crv = "Ed25519"
		x := byteBuffer(base64.RawURLEncoding.EncodeToString(key))
		representation.X = &x
	default:
		return vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("unsupported JWK key type %T", key))
	}

	return nil
}

var _ vapi.Encoder[*Jwk, EncoderOption] = &Encoder{}
