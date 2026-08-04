package clientcredentials

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/veles-security/vapi"
	"github.com/veles-security/voauth/token"
)

type Writer struct {
	tokenEncoder token.AnyTokenEncoder
}

type WriterConfigOption func(*Writer) error

type WriteFunc func(ctx context.Context, carrier *http.Request, artifact *ClientCredentials) error

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
	return writer, nil
}

// WithTokenEncoder configures the encoder used for client assertions.
func WithTokenEncoder(encoder token.AnyTokenEncoder) WriterConfigOption {
	return func(writer *Writer) error {
		if encoder == nil {
			return errors.New("nil token encoder")
		}
		writer.tokenEncoder = encoder
		return nil
	}
}

// WriteArtifact implements [vapi.Writer].
func (w *Writer) WriteArtifact(ctx context.Context, carrier *http.Request, artifact *ClientCredentials, options ...WriterOption) error {
	if w == nil {
		return vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("cannot write client credentials with nil writer"))
	}
	if carrier == nil {
		return vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("cannot write client credentials to nil request"))
	}
	if artifact == nil {
		return vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("cannot write nil client credentials"))
	}
	if artifact.ClientAssertion != nil && w.tokenEncoder == nil {
		return vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("cannot write client assertion with nil token encoder"))
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

func (w *Writer) writeArtifact(ctx context.Context, carrier *http.Request, artifact *ClientCredentials) error {
	form := url.Values{}
	if artifact.ClientId != "" {
		form.Set("client_id", artifact.ClientId)
	}
	if artifact.ClientSecret != "" {
		form.Set("client_secret", artifact.ClientSecret)
	}
	if artifact.ClientAssertion != nil {
		encoded, err := w.tokenEncoder.EncodeAnyToken(ctx, artifact.ClientAssertion)
		if err != nil {
			return vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("encode client assertion: %w", err))
		}
		form.Set("client_assertion_type", artifact.ClientAssertionType)
		form.Set("client_assertion", string(encoded))
	}

	body := form.Encode()
	carrier.Body = io.NopCloser(strings.NewReader(body))
	carrier.ContentLength = int64(len(body))
	if carrier.Header == nil {
		carrier.Header = make(http.Header)
	}
	carrier.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return nil
}

var _ vapi.Writer[*http.Request, *ClientCredentials, WriterOption] = &Writer{}
