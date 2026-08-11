package tokenresponse

import (
	"errors"

	"github.com/veles-security/voauth/jwt"
	"github.com/veles-security/voauth/token"
)

// WithEncoderTokenEncoder configures the encoder used for access, refresh, and ID tokens.
func WithEncoderTokenEncoder(encoder token.AnyTokenEncoder) EncoderConfigOption {
	return func(target *Encoder) error {
		if encoder == nil {
			return errors.New("nil token encoder")
		}
		target.tokenEncoder = encoder
		return nil
	}
}

// WithEncoderTokenEncoderOptions configures the encoder used for access,
// refresh, and ID tokens by constructing it with the provided JWT encoder
// configuration options.
func WithEncoderTokenEncoderOptions(options ...jwt.EncoderConfigOption) EncoderConfigOption {
	return func(target *Encoder) error {
		encoder, err := jwt.NewEncoder(options...)
		if err != nil {
			return err
		}
		target.tokenEncoder = encoder
		return nil
	}
}

// WithEncoderRuntimeOptions configures encoder options that are applied to
// every Encode call before its per-call options.
func WithEncoderRuntimeOptions(options ...EncoderOption) EncoderConfigOption {
	return func(encoder *Encoder) error {
		encoder.runtimeOptions = append([]EncoderOption(nil), options...)
		return nil
	}
}
