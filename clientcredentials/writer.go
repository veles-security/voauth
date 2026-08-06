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
	"github.com/veles-security/voauth/jwt"
	"github.com/veles-security/voauth/token"
)

type Writer struct {
	tokenEncoder   token.AnyTokenEncoder
	runtimeOptions []WriterOption
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
	if writer.tokenEncoder == nil {
		encoder, err := jwt.NewEncoder()
		if err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, err)
		}
		writer.tokenEncoder = encoder
	}
	return writer, nil
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
	if w.tokenEncoder == nil {
		return vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("cannot write client assertion with nil token encoder"))
	}

	allOptions := make([]WriterOption, 0, len(w.runtimeOptions)+len(options))
	allOptions = append(allOptions, w.runtimeOptions...)
	allOptions = append(allOptions, options...)

	next := w.writeArtifact
	for index := len(allOptions) - 1; index >= 0; index-- {
		option := allOptions[index]
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
		if encoded == nil {
			return vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("encode client assertion returned nil payload"))
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
