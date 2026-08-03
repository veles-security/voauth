package clientcredentials

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/veles-security/vapi"
	"github.com/veles-security/voauth"
)

type Writer[T voauth.Token, TO any] struct {
	tokenEncoder vapi.Encoder[T, TO]
}

// WriteArtifact implements [vapi.Writer].
func (w *Writer[T, TO]) WriteArtifact(ctx context.Context, carrier *http.Request, artifact *ClientCredentials, options ...WriterOption) error {
	form := url.Values{}
	if artifact.ClientId != "" {
		form.Set("client_id", artifact.ClientId)
	}
	if artifact.ClientSecret != "" {
		form.Set("client_secret", artifact.ClientSecret)
	}
	if artifact.ClientAssertion != nil {
		token, ok := artifact.ClientAssertion.(T)
		if !ok || w.tokenEncoder == nil {
			return vapi.ErrMalformed
		}
		encoded, err := w.tokenEncoder.Encode(ctx, token)
		if err != nil {
			return vapi.ErrMalformed
		}
		form.Set("client_assertion_type", artifact.ClientAssertionType)
		form.Set("client_assertion", string(encoded))
	}

	body := form.Encode()
	carrier.Body = io.NopCloser(strings.NewReader(body))
	carrier.ContentLength = int64(len(body))
	carrier.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return nil
}

type WriterOption interface {
}

var _ vapi.Writer[*http.Request, *ClientCredentials, WriterOption] = &Writer[voauth.Token, any]{}
