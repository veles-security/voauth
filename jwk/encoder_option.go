package jwk

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

type thumbprintKidOption struct{}

// WithThumbprintKid calculates an absent kid from the JWK Thumbprint defined by
// RFC 7638. An explicitly supplied kid is always preserved.
func WithThumbprintKid() EncoderOption {
	return thumbprintKidOption{}
}

func (o thumbprintKidOption) Apply(next EncodeFunc) EncodeFunc {
	return func(ctx context.Context, artifact *Jwk, representation *JwkRepresentation) error {
		if err := next(ctx, artifact, representation); err != nil {
			return err
		}
		if representation.Kid != "" {
			return nil
		}

		thumbprint, err := o.jwkThumbprint(*representation)
		if err != nil {
			return err
		}
		representation.Kid = thumbprint
		return nil
	}
}

func (thumbprintKidOption) jwkThumbprint(jwk JwkRepresentation) (string, error) {
	var canonical []byte
	var err error

	switch jwk.Kty {
	case "oct":
		canonical, err = json.Marshal(struct {
			K   *byteBuffer `json:"k"`
			Kty string      `json:"kty"`
		}{jwk.K, jwk.Kty})
	case "RSA":
		canonical, err = json.Marshal(struct {
			E   *byteBuffer `json:"e"`
			Kty string      `json:"kty"`
			N   *byteBuffer `json:"n"`
		}{jwk.E, jwk.Kty, jwk.N})
	case "EC":
		canonical, err = json.Marshal(struct {
			Crv string      `json:"crv"`
			Kty string      `json:"kty"`
			X   *byteBuffer `json:"x"`
			Y   *byteBuffer `json:"y"`
		}{jwk.Crv, jwk.Kty, jwk.X, jwk.Y})
	case "OKP":
		canonical, err = json.Marshal(struct {
			Crv string      `json:"crv"`
			Kty string      `json:"kty"`
			X   *byteBuffer `json:"x"`
		}{jwk.Crv, jwk.Kty, jwk.X})
	default:
		return "", fmt.Errorf("cannot calculate thumbprint for JWK key type %q", jwk.Kty)
	}
	if err != nil {
		return "", fmt.Errorf("cannot serialize JWK thumbprint input: %w", err)
	}

	digest := sha256.Sum256(canonical)
	return base64.RawURLEncoding.EncodeToString(digest[:]), nil
}
