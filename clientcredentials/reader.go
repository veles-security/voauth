package clientcredentials

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/veles-security/vapi"
	"github.com/veles-security/voauth/jwt"
	"github.com/veles-security/voauth/token"
)

type Reader struct {
	tokenDecoder   token.AnyTokenDecoder
	runtimeOptions []ReaderOption
}

type ReaderConfigOption func(*Reader) error

type ReadFunc func(ctx context.Context, carrier *http.Request) (*ClientCredentials, error)

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
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, err)
		}
		reader.tokenDecoder = decoder
	}
	return reader, nil
}

// ReadArtifact implements [vapi.Reader].
func (r *Reader) ReadArtifact(ctx context.Context, carrier *http.Request, options ...ReaderOption) (*ClientCredentials, error) {
	if r == nil || r.tokenDecoder == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("cannot read client credentials with invalid reader configuration"))
	}
	if carrier == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("cannot read client credentials from nil request"))
	}

	allOptions := make([]ReaderOption, 0, len(r.runtimeOptions)+len(options))
	allOptions = append(allOptions, r.runtimeOptions...)
	allOptions = append(allOptions, options...)

	next := r.readArtifact
	for index := len(allOptions) - 1; index >= 0; index-- {
		if allOptions[index] == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("nil reader option at index %d", index))
		}
		wrapped := allOptions[index](next)
		if wrapped == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("reader option at index %d returned nil ReadFunc", index))
		}
		next = wrapped
	}
	return next(ctx, carrier)
}

func (r *Reader) readArtifact(ctx context.Context, carrier *http.Request) (*ClientCredentials, error) {
	method, err := r.clientAuthMethod(carrier)
	if err != nil {
		return nil, err
	}

	credentials := &ClientCredentials{AuthMethod: method}
	switch method {
	case ClientSecretBasicAuthMethod:
		clientID, clientSecret, _ := carrier.BasicAuth()
		credentials.ClientId, err = url.QueryUnescape(clientID)
		if err == nil {
			credentials.ClientSecret, err = url.QueryUnescape(clientSecret)
		}
		if err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("decode basic client credentials: %w", err))
		}
	case ClientSecretPostAuthMethod:
		credentials.ClientId = carrier.PostForm.Get("client_id")
		credentials.ClientSecret = carrier.PostForm.Get("client_secret")
	default: // JWT client assertion methods share the same wire representation.
		credentials.ClientId = carrier.PostForm.Get("client_id")
		credentials.ClientAssertionType = carrier.PostForm.Get("client_assertion_type")
		credentials.ClientAssertion, err = r.tokenDecoder.DecodeAnyToken(ctx, []byte(carrier.PostForm.Get("client_assertion")))
		if err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("decode client assertion: %w", err))
		}
		if credentials.ClientAssertion == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("decode client assertion returned nil artifact"))
		}
	}
	return credentials, nil
}

func (r *Reader) clientAuthMethod(carrier *http.Request) (string, error) {
	_, _, basic := carrier.BasicAuth()
	if err := carrier.ParseForm(); err != nil {
		return "", vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("parse client credentials form: %w", err))
	}
	secretPost := carrier.PostForm.Get("client_secret") != ""
	assertion := carrier.PostForm.Get("client_assertion") != ""
	methods := 0
	if basic {
		methods++
	}
	if secretPost {
		methods++
	}
	if assertion {
		methods++
	}
	if methods == 0 {
		return "", vapi.ErrNotApplicable
	}
	if methods != 1 {
		return "", vapi.NewErrorCategory(vapi.ErrUnauthenticated, errors.New("multiple client authentication methods"))
	}
	if basic {
		return ClientSecretBasicAuthMethod, nil
	}
	if secretPost {
		return ClientSecretPostAuthMethod, nil
	}
	return PrivateKeyJwtAuthMethod, nil
}

var _ vapi.Reader[*http.Request, *ClientCredentials, ReaderOption] = &Reader{}
