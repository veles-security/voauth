package tokenrequest

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"

	"github.com/veles-security/vapi"
	"github.com/veles-security/voauth/clientcredentials"
	"github.com/veles-security/voauth/jwt"
	"github.com/veles-security/voauth/token"
)

type Reader struct {
	tokenDecoder            token.AnyTokenDecoder
	assertionTokenDecoder   token.AnyTokenDecoder
	clientCredentialsReader vapi.Reader[*http.Request, *clientcredentials.ClientCredentials, clientcredentials.ReaderOption]
	runtimeOptions          []ReaderOption
}

type ReaderConfigOption func(*Reader) error

type ReadFunc func(ctx context.Context, carrier *http.Request) (*TokenRequest, error)

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
	if reader.clientCredentialsReader == nil {
		credentialsReader, err := clientcredentials.NewReader()
		if err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, err)
		}
		reader.clientCredentialsReader = credentialsReader
	}
	if reader.tokenDecoder == nil {
		decoder, err := jwt.NewDecoder()
		if err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, err)
		}
		reader.tokenDecoder = decoder
	}
	if reader.assertionTokenDecoder == nil {
		decoder, err := jwt.NewDecoder()
		if err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, err)
		}
		reader.assertionTokenDecoder = decoder
	}
	return reader, nil
}

// ReadArtifact implements [vapi.Reader].
func (r *Reader) ReadArtifact(ctx context.Context, carrier *http.Request, options ...ReaderOption) (*TokenRequest, error) {
	if r == nil || r.clientCredentialsReader == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("cannot read token request with nil client credentials reader"))
	}
	if carrier == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("cannot read token request from nil request"))
	}

	allOptions := slices.Concat(r.runtimeOptions, options)

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

func (r *Reader) readArtifact(ctx context.Context, carrier *http.Request) (*TokenRequest, error) {
	if err := carrier.ParseForm(); err != nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("parse token request form: %w", err))
	}

	request := &TokenRequest{GrantType: carrier.PostForm.Get("grant_type")}
	credentials, err := r.clientCredentialsReader.ReadArtifact(ctx, carrier)
	if err == nil {
		if credentials == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("read client credentials returned nil artifact"))
		}
		request.ClientCredentials = *credentials
	} else if !errors.Is(err, vapi.ErrNotApplicable) {
		return nil, fmt.Errorf("read client credentials: %w", err)
	}

	switch request.GrantType {
	case AuthorizationCodeGrantType:
		request.Code = carrier.PostForm.Get("code")
		request.RedirectUri = carrier.PostForm.Get("redirect_uri")
		request.CodeVerifier = carrier.PostForm.Get("code_verifier")
	case PasswordGrantType:
		request.Username = carrier.PostForm.Get("username")
		request.Password = carrier.PostForm.Get("password")
		request.Scope = carrier.PostForm.Get("scope")
	case ClientCredentialsGrantType:
		request.Scope = carrier.PostForm.Get("scope")
	case RefreshTokenGrantType:
		encoded := carrier.PostForm.Get("refresh_token")
		if encoded != "" {
			if r.tokenDecoder == nil {
				return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("cannot read refresh token with nil token decoder"))
			}
			request.RefreshToken, err = r.tokenDecoder.DecodeAnyToken(ctx, []byte(encoded))
			if err != nil {
				return nil, vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("decode refresh token: %w", err))
			}
			if request.RefreshToken == nil {
				return nil, vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("decode refresh token returned nil artifact"))
			}
		}
		request.Scope = carrier.PostForm.Get("scope")
	case DeviceCodeGrantType:
		request.DeviceCode = carrier.PostForm.Get("device_code")
	case JwtBearerGrantType, Saml2BearerGrantType:
		encoded := carrier.PostForm.Get("assertion")
		if encoded != "" {
			if r.assertionTokenDecoder == nil {
				return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("cannot read bearer assertion with nil assertion token decoder"))
			}
			request.Assertion, err = r.assertionTokenDecoder.DecodeAnyToken(ctx, []byte(encoded))
			if err != nil {
				return nil, vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("decode bearer assertion: %w", err))
			}
			if request.Assertion == nil {
				return nil, vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("decode bearer assertion returned nil artifact"))
			}
		}
	}
	return request, nil
}

var _ vapi.Reader[*http.Request, *TokenRequest, ReaderOption] = &Reader{}
