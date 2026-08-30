package tokenresponse

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"

	"github.com/veles-security/vapi"
)

type Reader struct {
	decoder        vapi.Decoder[*TokenResponse, DecoderOption]
	runtimeOptions []ReaderOption
}

type ReaderConfigOption func(*Reader) error

type ReadFunc func(ctx context.Context, carrier *http.Response) (*TokenResponse, error)

type ReaderOption func(next ReadFunc) ReadFunc

func NewReader(configOptions ...ReaderConfigOption) (*Reader, error) {
	reader := &Reader{}
	for _, option := range configOptions {
		if option == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("nil reader config option"))
		}
		if err := option(reader); err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, err)
		}
	}
	if reader.decoder == nil {
		decoder, err := NewDecoder()
		if err != nil {
			return nil, err
		}
		reader.decoder = decoder
	}
	return reader, nil
}

// ReadArtifact implements [vapi.Reader].
func (r *Reader) ReadArtifact(ctx context.Context, carrier *http.Response, options ...ReaderOption) (*TokenResponse, error) {
	if r == nil || r.decoder == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("cannot read token response with nil decoder"))
	}
	if carrier == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("cannot read token response from nil HTTP response"))
	}
	if carrier.Body == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("cannot read token response with nil body"))
	}

	allOptions := slices.Concat(w.runtimeOptions, options)

	next := r.readArtifact
	for index := len(allOptions) - 1; index >= 0; index-- {
		option := allOptions[index]
		if option == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("nil reader option at index %d", index))
		}
		wrapped := option(next)
		if wrapped == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("reader option at index %d returned nil ReadFunc", index))
		}
		next = wrapped
	}

	return next(ctx, carrier)
}

func (r *Reader) readArtifact(ctx context.Context, carrier *http.Response) (*TokenResponse, error) {
	payload, err := io.ReadAll(carrier.Body)
	if err != nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("read token response: %w", err))
	}

	artifact, err := r.decoder.Decode(ctx, payload)
	if err != nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("decode token response: %w", err))
	}
	if artifact == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("decode token response returned nil artifact"))
	}
	return artifact, nil
}

var _ vapi.Reader[*http.Response, *TokenResponse, ReaderOption] = &Reader{}
