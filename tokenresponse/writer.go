package tokenresponse

import (
	"context"
	"errors"
	"net/http"

	"github.com/veles-security/vapi"
	"github.com/veles-security/voauth/jwt"
	"github.com/veles-security/voauth/token"
)

type Writer struct {
	tokenEncoder token.AnyTokenEncoder
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
	if writer.tokenEncoder == nil {
		tokenEcoder, err := jwt.NewEncoder()
		if err != nil {
			return nil, err
		}
		writer.tokenEncoder = tokenEcoder
	}
	return writer, nil
}

// WriteArtifact implements [vapi.Writer].
func (w *Writer) WriteArtifact(ctx context.Context, carrierWriter http.ResponseWriter, artifact *TokenResponse, options ...WriterOption) error {
	panic("unimplemented")
}

var _ vapi.Writer[http.ResponseWriter, *TokenResponse, WriterOption] = &Writer{}
