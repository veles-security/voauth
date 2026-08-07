package jwt

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/veles-security/vapi"
)

type Reader struct {
	decoder        vapi.Decoder[*Token, DecoderOption]
	runtimeOptions []ReaderOption
}

type ReaderConfigOption func(*Reader) error

type ReadFunc func(ctx context.Context, carrier *http.Request) (*Token, error)

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
func (r *Reader) ReadArtifact(ctx context.Context, carrier *http.Request, options ...ReaderOption) (*Token, error) {
	if r == nil || r.decoder == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("cannot read JWT with nil JWT decoder"))
	}
	if carrier == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("cannot read JWT from nil request"))
	}

	allOptions := make([]ReaderOption, 0, len(r.runtimeOptions)+len(options))
	allOptions = append(allOptions, r.runtimeOptions...)
	allOptions = append(allOptions, options...)

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

func (r *Reader) readArtifact(ctx context.Context, carrier *http.Request) (*Token, error) {
	values := carrier.Header.Values("Authorization")
	if len(values) == 0 {
		return nil, vapi.ErrNotApplicable
	}
	if len(values) != 1 {
		return nil, vapi.NewErrorCategory(vapi.ErrUnauthenticated, errors.New("ambiguous authorization credentials"))
	}

	scheme, credential, found := strings.Cut(values[0], " ")
	if !strings.EqualFold(scheme, "Bearer") {
		return nil, vapi.ErrNotApplicable
	}
	if !found || credential == "" || strings.ContainsAny(credential, " \t\r\n,") {
		return nil, vapi.NewErrorCategory(vapi.ErrUnauthenticated, errors.New("malformed bearer credentials"))
	}

	artifact, err := r.decoder.Decode(ctx, []byte(credential))
	if err != nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("decode JWT: %w", err))
	}
	if artifact == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("decode JWT returned nil artifact"))
	}
	return artifact, nil
}

var _ vapi.Reader[*http.Request, *Token, ReaderOption] = &Reader{}
