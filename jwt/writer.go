package jwt

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/veles-security/vapi"
)

type Writer struct {
	encoder vapi.Encoder[*Token, EncoderOption]
}

type WriterConfigOption func(*Writer) error

type WriteFunc func(ctx context.Context, carrier *http.Request, artifact *Token) error

type WriterOption func(next WriteFunc) WriteFunc

func NewWriter(configOptions ...WriterConfigOption) (*Writer, error) {
	writer := &Writer{}
	for _, option := range configOptions {
		if option == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("nil writer config option"))
		}
		if err := option(writer); err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, err)
		}
	}
	if writer.encoder == nil {
		encoder, err := NewEncoder()
		if err != nil {
			return nil, err
		}
		writer.encoder = encoder
	}
	return writer, nil
}

// WithEncoder configures the encoder used to encode JWTs.
func WithEncoder(encoder vapi.Encoder[*Token, EncoderOption]) WriterConfigOption {
	return func(writer *Writer) error {
		if encoder == nil {
			return errors.New("nil JWT encoder")
		}
		writer.encoder = encoder
		return nil
	}
}

// WriteArtifact implements [vapi.Writer].
func (w *Writer) WriteArtifact(ctx context.Context, carrier *http.Request, artifact *Token, options ...WriterOption) error {
	if w == nil || w.encoder == nil {
		return vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("cannot write JWT with nil JWT encoder"))
	}
	if carrier == nil {
		return vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("cannot write JWT to nil request"))
	}
	if artifact == nil {
		return vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("cannot write nil JWT"))
	}

	next := w.writeArtifact
	for index := len(options) - 1; index >= 0; index-- {
		option := options[index]
		if option == nil {
			return vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("nil writer option at index %d", index))
		}
		wrapped := option(next)
		if wrapped == nil {
			return vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("writer option at index %d returned nil WriteFunc", index))
		}
		next = wrapped
	}

	return next(ctx, carrier, artifact)
}

func (w *Writer) writeArtifact(ctx context.Context, carrier *http.Request, artifact *Token) error {
	raw, err := w.encoder.Encode(ctx, artifact)
	if err != nil {
		return vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("encode JWT: %w", err))
	}
	if carrier.Header == nil {
		carrier.Header = make(http.Header)
	}
	carrier.Header.Set("Authorization", "Bearer "+string(raw))
	return nil
}

var _ vapi.Writer[*http.Request, *Token, WriterOption] = &Writer{}
