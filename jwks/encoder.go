package jwks

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/veles-security/vapi"
	"github.com/veles-security/voauth/jwk"
)

type Encoder struct {
	jwkEncoder vapi.Encoder[*jwk.Jwk, jwk.EncoderOption]
}

type EncoderOption func(*Encoder)

func NewEncoder(options ...EncoderOption) *Encoder {
	encoder := &Encoder{}
	encoder.jwkEncoder = &jwk.Encoder{}
	for _, option := range options {
		option(encoder)
	}
	return encoder
}

// Encode implements [vapi.Encoder].
func (j *Encoder) Encode(ctx context.Context, artifact *Jwks, options ...EncoderOption) ([]byte, error) {
	if artifact == nil || artifact.Jwk == nil {
		return nil, fmt.Errorf("cannot encode nil JWK")
	}
	if len(artifact.Jwk) == 0 {
		return nil, fmt.Errorf("cannot encode empty JWK set")
	}
	representation := JwksRepresentation{Keys: make([]jwk.JwkRepresentation, len(artifact.Jwk))}
	for i := range artifact.Jwk {
		encoded, err := j.jwkEncoder.Encode(ctx, &artifact.Jwk[i])
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(encoded, &representation.Keys[i]); err != nil {
			return nil, err
		}
	}
	return json.Marshal(representation)
}

var _ vapi.Encoder[*Jwks, EncoderOption] = &Encoder{}
