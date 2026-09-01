package tokenresponse

import (
	"errors"

	"github.com/veles-security/vapi"
)

// WithReaderMaxBodyBytes configures the maximum token response body size.
func WithReaderMaxBodyBytes(maxBytes int64) ReaderConfigOption {
	return func(reader *Reader) error {
		if maxBytes <= 0 {
			return errors.New("maximum token response body size must be positive")
		}
		reader.maxBodyBytes = maxBytes
		return nil
	}
}

// WithReaderDecoder configures the decoder used to decode token responses.
func WithReaderDecoder(decoder vapi.Decoder[*TokenResponse, DecoderOption]) ReaderConfigOption {
	return func(target *Reader) error {
		if decoder == nil {
			return errors.New("nil token response decoder")
		}
		target.decoder = decoder
		return nil
	}
}

// WithReaderDecoderOptions constructs the decoder used to decode token responses
// with the provided configuration options.
func WithReaderDecoderOptions(options ...DecoderConfigOption) ReaderConfigOption {
	return func(reader *Reader) error {
		decoder, err := NewDecoder(options...)
		if err != nil {
			return err
		}
		reader.decoder = decoder
		return nil
	}
}

// WithReaderRuntimeOptions configures reader options that are applied to every
// ReadArtifact call before its per-call options.
func WithReaderRuntimeOptions(options ...ReaderOption) ReaderConfigOption {
	return func(reader *Reader) error {
		reader.runtimeOptions = append([]ReaderOption(nil), options...)
		return nil
	}
}
