package tokenresponse

import (
	"context"
	"errors"
	"net/http"

	"github.com/veles-security/vapi"
	"github.com/veles-security/voauth/jwt"
	"github.com/veles-security/voauth/token"
)

type Reader struct {
	tokenDecoder token.AnyTokenDecoder
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
	if reader.tokenDecoder == nil {
		decoder, err := jwt.NewDecoder()
		if err != nil {
			return nil, err
		}
		reader.tokenDecoder = decoder
	}
	return reader, nil
}

// ReadArtifact implements [vapi.Reader].
func (r *Reader) ReadArtifact(ctx context.Context, carrier *http.Response, options ...ReaderOption) (*TokenResponse, error) {
	panic("unimplemented")
}

var _ vapi.Reader[*http.Response, *TokenResponse, ReaderOption] = &Reader{}
