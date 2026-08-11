package tokenresponse

import (
	"errors"

	"github.com/veles-security/voauth/jwt"
	"github.com/veles-security/voauth/token"
)

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
