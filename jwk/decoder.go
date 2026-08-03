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
	"fmt"
	"math"
	"math/big"

	"github.com/veles-security/vapi"
	"github.com/veles-security/vapi/sig"
)

type Decoder struct{}

type DecoderOption func(*Decoder)

func NewDecoder(options ...DecoderOption) *Decoder {
	encoder := &Decoder{}
	for _, option := range options {
		option(encoder)
	}
	return encoder
}

// Encode implements [vapi.Decoder].
func (j *Decoder) Decode(ctx context.Context, payload []byte, options ...DecoderOption) (*Jwk, error) {
	var representation JwkRepresentation
	if err := json.Unmarshal(payload, &representation); err != nil {
		return nil, err
	}

	alg, err := sig.NewSigAlgFromOAuth(representation.Alg)
	if err != nil {
		return nil, err
	}
	result := &Jwk{}
	result.Kid = representation.Kid
	result.Alg = alg

	switch representation.Kty {
	case "oct":
		if representation.K == nil {
			return nil, fmt.Errorf("missing JWK key parameter k")
		}
		key, err := base64.RawURLEncoding.DecodeString(string(*representation.K))
		if err != nil {
			return nil, fmt.Errorf("invalid JWK key parameter k: %w", err)
		}
		result.Key = key
	case "RSA":
		if representation.N == nil || representation.E == nil {
			return nil, fmt.Errorf("missing RSA JWK key parameters")
		}
		n, err := base64.RawURLEncoding.DecodeString(string(*representation.N))
		if err != nil {
			return nil, fmt.Errorf("invalid RSA modulus: %w", err)
		}
		e, err := base64.RawURLEncoding.DecodeString(string(*representation.E))
		if err != nil {
			return nil, fmt.Errorf("invalid RSA exponent: %w", err)
		}
		if len(e) == 0 || len(e) > 8 {
			return nil, fmt.Errorf("invalid RSA exponent")
		}
		var exponent [8]byte
		copy(exponent[8-len(e):], e)
		exponentValue := binary.BigEndian.Uint64(exponent[:])
		if exponentValue == 0 || exponentValue > math.MaxInt {
			return nil, fmt.Errorf("invalid RSA exponent")
		}
		result.Key = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(exponentValue)}
	case "EC":
		if representation.X == nil || representation.Y == nil {
			return nil, fmt.Errorf("missing EC JWK key parameters")
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
			return nil, fmt.Errorf("unsupported elliptic curve %q", representation.Crv)
		}
		x, err := base64.RawURLEncoding.DecodeString(string(*representation.X))
		if err != nil {
			return nil, fmt.Errorf("invalid EC x coordinate: %w", err)
		}
		y, err := base64.RawURLEncoding.DecodeString(string(*representation.Y))
		if err != nil {
			return nil, fmt.Errorf("invalid EC y coordinate: %w", err)
		}
		xValue, yValue := new(big.Int).SetBytes(x), new(big.Int).SetBytes(y)
		if !curve.IsOnCurve(xValue, yValue) {
			return nil, fmt.Errorf("EC JWK point is not on curve %q", representation.Crv)
		}
		result.Key = &ecdsa.PublicKey{Curve: curve, X: xValue, Y: yValue}
	case "OKP":
		if representation.Crv != "Ed25519" || representation.X == nil {
			return nil, fmt.Errorf("unsupported OKP JWK curve %q", representation.Crv)
		}
		key, err := base64.RawURLEncoding.DecodeString(string(*representation.X))
		if err != nil {
			return nil, fmt.Errorf("invalid Ed25519 key: %w", err)
		}
		if len(key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid Ed25519 key length %d", len(key))
		}
		result.Key = ed25519.PublicKey(key)
	default:
		return nil, fmt.Errorf("unsupported JWK key type %q", representation.Kty)
	}

	return result, nil
}

var _ vapi.Decoder[*Jwk, DecoderOption] = &Decoder{}
