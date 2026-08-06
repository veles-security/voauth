package jwk

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"

	"github.com/veles-security/vapi"
	"github.com/veles-security/vapi/sig"
)

type Decoder struct{}

type DecoderConfigOption func(*Decoder) error

type DecodeFunc func(ctx context.Context, payload []byte) (*Jwk, error)

type DecoderOption func(next DecodeFunc) DecodeFunc

func NewDecoder(configOptions ...DecoderConfigOption) (*Decoder, error) {
	decoder := &Decoder{}
	for _, option := range configOptions {
		if option == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("nil decoder config option"))
		}
		if err := option(decoder); err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, err)
		}
	}
	return decoder, nil
}

// Decode implements [vapi.Decoder].
func (d *Decoder) Decode(ctx context.Context, payload []byte, options ...DecoderOption) (*Jwk, error) {
	if d == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("cannot decode JWK with nil decoder"))
	}
	if payload == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("cannot decode nil JWK payload"))
	}

	next := d.decode
	for index := len(options) - 1; index >= 0; index-- {
		option := options[index]
		if option == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("nil decoder option at index %d", index))
		}
		wrapped := option(next)
		if wrapped == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("decoder option at index %d returned nil DecodeFunc", index))
		}
		next = wrapped
	}

	return next(ctx, payload)
}

func (d *Decoder) decode(_ context.Context, payload []byte) (*Jwk, error) {
	var representation JwkRepresentation
	if err := json.Unmarshal(payload, &representation); err != nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("decode JWK representation: %w", err))
	}

	alg, err := sig.NewSigAlgFromOAuth(representation.Alg)
	if err != nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("decode JWK algorithm: %w", err))
	}
	result := &Jwk{}
	result.Kid = representation.Kid
	result.Alg = alg

	switch representation.Kty {
	case "oct":
		if representation.K == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("missing JWK key parameter k"))
		}
		key, err := base64.RawURLEncoding.DecodeString(string(*representation.K))
		if err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("invalid JWK key parameter k: %w", err))
		}
		result.Key = key
	case "RSA":
		if representation.N == nil || representation.E == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("missing RSA JWK key parameters"))
		}
		n, err := base64.RawURLEncoding.DecodeString(string(*representation.N))
		if err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("invalid RSA modulus: %w", err))
		}
		e, err := base64.RawURLEncoding.DecodeString(string(*representation.E))
		if err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("invalid RSA exponent: %w", err))
		}
		if len(e) == 0 || len(e) > 8 {
			return nil, vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("invalid RSA exponent"))
		}
		var exponent [8]byte
		copy(exponent[8-len(e):], e)
		exponentValue := binary.BigEndian.Uint64(exponent[:])
		if exponentValue == 0 || exponentValue > math.MaxInt {
			return nil, vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("invalid RSA exponent"))
		}
		result.Key = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(exponentValue)}
	case "EC":
		if representation.X == nil || representation.Y == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("missing EC JWK key parameters"))
		}
		var curve elliptic.Curve
		switch representation.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("unsupported elliptic curve %q", representation.Crv))
		}
		x, err := base64.RawURLEncoding.DecodeString(string(*representation.X))
		if err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("invalid EC x coordinate: %w", err))
		}
		y, err := base64.RawURLEncoding.DecodeString(string(*representation.Y))
		if err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("invalid EC y coordinate: %w", err))
		}
		xValue, yValue := new(big.Int).SetBytes(x), new(big.Int).SetBytes(y)
		if !curve.IsOnCurve(xValue, yValue) {
			return nil, vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("EC JWK point is not on curve %q", representation.Crv))
		}
		result.Key = &ecdsa.PublicKey{Curve: curve, X: xValue, Y: yValue}
	case "OKP":
		if representation.Crv != "Ed25519" || representation.X == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("unsupported OKP JWK curve %q", representation.Crv))
		}
		key, err := base64.RawURLEncoding.DecodeString(string(*representation.X))
		if err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("invalid Ed25519 key: %w", err))
		}
		if len(key) != ed25519.PublicKeySize {
			return nil, vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("invalid Ed25519 key length %d", len(key)))
		}
		result.Key = ed25519.PublicKey(key)
	default:
		return nil, vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("unsupported JWK key type %q", representation.Kty))
	}

	return result, nil
}

var _ vapi.Decoder[*Jwk, DecoderOption] = &Decoder{}
