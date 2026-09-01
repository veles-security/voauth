package jwt

import "errors"

// WithDecoderMaxTokenBytes configures the maximum compact JWT size.
func WithDecoderMaxTokenBytes(maxBytes int) DecoderConfigOption {
	return func(decoder *Decoder) error {
		if maxBytes <= 0 {
			return errors.New("maximum JWT size must be positive")
		}
		decoder.maxTokenBytes = maxBytes
		return nil
	}
}

// WithDecoderMaxHeaderBytes configures the maximum decoded JWT header size.
func WithDecoderMaxHeaderBytes(maxBytes int) DecoderConfigOption {
	return func(decoder *Decoder) error {
		if maxBytes <= 0 {
			return errors.New("maximum JWT header size must be positive")
		}
		decoder.maxHeaderBytes = maxBytes
		return nil
	}
}

// WithDecoderMaxClaimsBytes configures the maximum decoded JWT claims size.
func WithDecoderMaxClaimsBytes(maxBytes int) DecoderConfigOption {
	return func(decoder *Decoder) error {
		if maxBytes <= 0 {
			return errors.New("maximum JWT claims size must be positive")
		}
		decoder.maxClaimsBytes = maxBytes
		return nil
	}
}

// WithDecoderMaxSignatureBytes configures the maximum decoded JWT signature size.
func WithDecoderMaxSignatureBytes(maxBytes int) DecoderConfigOption {
	return func(decoder *Decoder) error {
		if maxBytes <= 0 {
			return errors.New("maximum JWT signature size must be positive")
		}
		decoder.maxSignatureBytes = maxBytes
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
