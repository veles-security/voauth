package voauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/veles-security/vapi"
)

type JwkRepresentation struct {
	Use       string      `json:"use,omitempty"`
	Kty       string      `json:"kty,omitempty"`
	Kid       string      `json:"kid,omitempty"`
	Crv       string      `json:"crv,omitempty"`
	Alg       string      `json:"alg,omitempty"`
	K         *byteBuffer `json:"k,omitempty"`
	X         *byteBuffer `json:"x,omitempty"`
	Y         *byteBuffer `json:"y,omitempty"`
	N         *byteBuffer `json:"n,omitempty"`
	E         *byteBuffer `json:"e,omitempty"`
	X5c       []string    `json:"x5c,omitempty"`
	X5u       *url.URL    `json:"x5u,omitempty"`
	X5tSHA1   string      `json:"x5t,omitempty"`
	X5tSHA256 string      `json:"x5t#S256,omitempty"`
}

type byteBuffer string

type JwkEncoder struct{}

type JwkEncoderOption func(*JwkEncoder)

func NewJwkEncoder(options ...JwkEncoderOption) *JwkEncoder {
	encoder := &JwkEncoder{}
	for _, option := range options {
		option(encoder)
	}
	return encoder
}

// Encode implements [vapi.Encoder].
func (j *JwkEncoder) Encode(ctx context.Context, artifact *Jwk, options ...JwkEncoderOption) ([]byte, error) {
	if artifact == nil || artifact.Key.Key == nil {
		return nil, fmt.Errorf("cannot encode nil JWK or key")
	}

	alg, err := artifact.Alg.ToOAuth()
	if err != nil {
		return nil, err
	}
	representation := JwkRepresentation{Alg: alg, Kid: artifact.Key.Kid}

	switch key := artifact.Key.Key.Public().(type) {
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

	return json.Marshal(representation)
}

var _ vapi.Encoder[*Jwk, JwkEncoderOption] = &JwkEncoder{}
