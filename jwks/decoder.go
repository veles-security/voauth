package jwks

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/veles-security/vapi"
	"github.com/veles-security/voauth/jwk"
)

type Decoder struct {
	jwkDecoder vapi.Decoder[*jwk.Jwk, jwk.DecoderOption]
}

type DecoderOption func(*Decoder)

func NewDecoder(options ...DecoderOption) *Decoder {
	decoder := &Decoder{}
	decoder.jwkDecoder = &jwk.Decoder{}
	for _, option := range options {
		option(decoder)
	}
	return decoder
}

// Encode implements [vapi.Decoder].
func (j *Decoder) Decode(ctx context.Context, payload []byte, options ...DecoderOption) (*Jwks, error) {
	var representation JwksRepresentation
	if err := json.Unmarshal(payload, &representation); err != nil {
		return nil, err
	}
	if representation.Keys == nil {
		return nil, fmt.Errorf("missing JWK set keys")
	}
	if len(representation.Keys) == 0 {
		return nil, fmt.Errorf("cannot decode empty JWK set")
	}

	result := &Jwks{Keys: make([]jwk.Jwk, len(representation.Keys))}
	for i := range representation.Keys {
		encoded, err := json.Marshal(&representation.Keys[i])
		if err != nil {
			return nil, err
		}
		decoded, err := j.jwkDecoder.Decode(ctx, encoded)
		if err != nil {
			return nil, err
		}
		result.Keys[i] = *decoded
	}
	return result, nil
}

var _ vapi.Decoder[*Jwks, DecoderOption] = &Decoder{}
