package jwk

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/veles-security/vapi"
)

type Encoder struct {
	options []EncoderOption
}

type EncoderOption interface {
	Configure(*Encoder)
	Apply(*Jwk, *JwkRepresentation) error
}

func NewEncoder(options ...EncoderOption) *Encoder {
	encoder := &Encoder{}
	for _, option := range options {
		option.Configure(encoder)
	}
	return encoder
}

// Encode implements [vapi.Encoder].
func (j *Encoder) Encode(ctx context.Context, artifact *Jwk, options ...EncoderOption) ([]byte, error) {
	if artifact == nil || artifact.Key == nil {
		return nil, fmt.Errorf("cannot encode nil JWK or key")
	}

	alg, err := artifact.Alg.ToOAuth()
	if err != nil {
		return nil, err
	}
	representation := JwkRepresentation{Alg: alg, Kid: artifact.Kid}

	switch key := artifact.Key.(type) {
	case []byte:
		representation.Kty = "oct"
		encoded := byteBuffer(base64.RawURLEncoding.EncodeToString(key))
		representation.K = &encoded
	case *rsa.PublicKey:
		representation.Kty = "RSA"
		n := byteBuffer(base64.RawURLEncoding.EncodeToString(key.N.Bytes()))
		representation.N = &n
		var exponent [8]byte
		binary.BigEndian.PutUint64(exponent[:], uint64(key.E))
		start := 0
		for start < len(exponent)-1 && exponent[start] == 0 {
			start++
		}
		e := byteBuffer(base64.RawURLEncoding.EncodeToString(exponent[start:]))
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
			return nil, fmt.Errorf("unsupported elliptic curve %q", key.Curve.Params().Name)
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
		return nil, fmt.Errorf("unsupported JWK key type %T", key)
	}

	for _, option := range append(j.options[:len(j.options):len(j.options)], options...) {
		if err := option.Apply(artifact, &representation); err != nil {
			return nil, err
		}
	}

	return json.Marshal(representation)
}

var _ vapi.Encoder[*Jwk, EncoderOption] = &Encoder{}
