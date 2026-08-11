package tokenresponse

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/veles-security/vapi"
)

type Writer struct {
	encoder        vapi.Encoder[*TokenResponse, EncoderOption]
	runtimeOptions []WriterOption
}

type WriterConfigOption func(*Writer) error

type WriteFunc func(ctx context.Context, carrierWriter http.ResponseWriter, artifact *TokenResponse) error

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

// WriteArtifact implements [vapi.Writer].
func (w *Writer) WriteArtifact(ctx context.Context, carrierWriter http.ResponseWriter, artifact *TokenResponse, options ...WriterOption) error {
	if w == nil || w.encoder == nil {
		return vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("cannot write token response with nil encoder"))
	}
	if carrierWriter == nil {
		return vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("cannot write token response to nil HTTP response writer"))
	}
	if artifact == nil {
		return vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("cannot write nil token response"))
	}

	allOptions := make([]WriterOption, 0, len(w.runtimeOptions)+len(options))
	allOptions = append(allOptions, w.runtimeOptions...)
	allOptions = append(allOptions, options...)

	next := w.writeArtifact
	for index := len(allOptions) - 1; index >= 0; index-- {
		if allOptions[index] == nil {
			return vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("nil writer option at index %d", index))
		}
		next = allOptions[index](next)
		if next == nil {
			return vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("writer option at index %d returned nil WriteFunc", index))
		}
	}

	return next(ctx, carrierWriter, artifact)
}

func (w *Writer) writeArtifact(ctx context.Context, carrierWriter http.ResponseWriter, artifact *TokenResponse) error {
	payload, err := w.encoder.Encode(ctx, artifact)
	if err != nil {
		return vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("encode token response: %w", err))
	}

	header := carrierWriter.Header()
	header.Set("Content-Type", "application/json;charset=UTF-8")
	header.Set("Cache-Control", "no-store")
	header.Set("Pragma", "no-cache")
	carrierWriter.WriteHeader(http.StatusOK)
	if _, err = carrierWriter.Write(payload); err != nil {
		return vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("write token response: %w", err))
	}
	return nil
}

var _ vapi.Writer[http.ResponseWriter, *TokenResponse, WriterOption] = &Writer{}
