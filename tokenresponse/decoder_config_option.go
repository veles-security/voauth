package tokenresponse

import (
	"errors"

	"github.com/veles-security/voauth/jwt"
	"github.com/veles-security/voauth/token"
)

// WithDecoderMaxPayloadBytes configures the maximum JSON token response size.
func WithDecoderMaxPayloadBytes(maxBytes int) DecoderConfigOption {
	return func(decoder *Decoder) error {
		if maxBytes <= 0 {
			return errors.New("maximum token response payload size must be positive")
		}
		decoder.maxPayloadBytes = maxBytes
		return nil
	}
}

// WithDecoderTokenDecoder configures the decoder used for access, refresh, and ID tokens.
func WithDecoderTokenDecoder(decoder token.AnyTokenDecoder) DecoderConfigOption {
	return func(target *Decoder) error {
		if decoder == nil {
			return errors.New("nil token decoder")
		}
		target.tokenDecoder = decoder
		return nil
	}
}

// WithDecoderTokenDecoderOptions configures the decoder used for access,
// refresh, and ID tokens by constructing it with the provided JWT decoder
// configuration options.
func WithDecoderTokenDecoderOptions(options ...jwt.DecoderConfigOption) DecoderConfigOption {
	return func(target *Decoder) error {
		decoder, err := jwt.NewDecoder(options...)
		if err != nil {
			return err
		}
		target.tokenDecoder = decoder
		return nil
	}
}

// WithDecoderRuntimeOptions configures decoder options that are applied to
// every Decode call before its per-call options.
func WithDecoderRuntimeOptions(options ...DecoderOption) DecoderConfigOption {
	return func(decoder *Decoder) error {
		decoder.runtimeOptions = append([]DecoderOption(nil), options...)
		return nil
	}
}
