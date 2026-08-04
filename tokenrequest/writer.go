package tokenrequest

import (
	"context"
	"errors"
	"net/http"

	"github.com/veles-security/vapi"
	"github.com/veles-security/voauth/clientcredentials"
	"github.com/veles-security/voauth/token"
)

type Writer struct {
	tokenEncoder             token.AnyTokenEncoder
	assertionTokenEncoder    token.AnyTokenEncoder
	clientCredentialsEncoder *clientcredentials.Writer
}

type WriterConfigOption func(*Writer) error

type WriteFunc func(ctx context.Context, carrier *http.Request, artifact *TokenRequest) error

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

// WriteArtifact implements [vapi.Writer].
func (w *Writer) WriteArtifact(ctx context.Context, carrierWriter *http.Request, artifact *TokenRequest, options ...WriterOption) error {
	panic("unimplemented")
}

var _ vapi.Writer[*http.Request, *TokenRequest, WriterOption] = &Writer{}
