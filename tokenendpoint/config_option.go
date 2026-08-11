package tokenendpoint

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/veles-security/vapi"
	"github.com/veles-security/voauth/jwt"
	"github.com/veles-security/voauth/tokenrequest"
	"github.com/veles-security/voauth/tokenresponse"
)

func WithTokenRequestAuthenticator(authenticator vapi.Authenticator[*http.Request]) TokenEndpointConfigOption {
	return func(endpoint *TokenEndpoint) error {
		if authenticator == nil {
			return errors.New("nil token request authenticator")
		}
		endpoint.requestAuthenticator = authenticator
		return nil
	}
}

func WithTokenRequestAuthenticatorOptions(options ...tokenrequest.AuthenticatorConfigOption) TokenEndpointConfigOption {
	return func(endpoint *TokenEndpoint) error {
		authenticator, err := tokenrequest.NewAuthenticator(options...)
		if err != nil {
			return err
		}
		endpoint.requestAuthenticator = authenticator
		return nil
	}
}

func WithIssuer(issuer vapi.Issuer[jwt.IssuerOption, *jwt.Token]) TokenEndpointConfigOption {
	return func(endpoint *TokenEndpoint) error {
		if issuer == nil {
			return errors.New("nil issuer")
		}
		endpoint.issuer = issuer
		return nil
	}
}

func WithIssuerOptions(options ...jwt.IssuerConfigOption) TokenEndpointConfigOption {
	return func(endpoint *TokenEndpoint) error {
		issuer, err := jwt.NewIssuer(options...)
		if err != nil {
			return err
		}
		endpoint.issuer = issuer
		return nil
	}
}

func WithTokenResponseWriter(writer vapi.Writer[http.ResponseWriter, *tokenresponse.TokenResponse, tokenresponse.WriterOption]) TokenEndpointConfigOption {
	return func(endpoint *TokenEndpoint) error {
		if writer == nil {
			return errors.New("nil token response writer")
		}
		endpoint.responseWriter = writer
		return nil
	}
}

func WithTokenResponseWriterOptions(options ...tokenresponse.WriterConfigOption) TokenEndpointConfigOption {
	return func(endpoint *TokenEndpoint) error {
		writer, err := tokenresponse.NewWriter(options...)
		if err != nil {
			return err
		}
		endpoint.responseWriter = writer
		return nil
	}
}

func WithIssuedTokens(tokens ...IssuedToken) TokenEndpointConfigOption {
	return func(endpoint *TokenEndpoint) error {
		if len(tokens) == 0 {
			return errors.New("no issued tokens")
		}
		issued := make(map[IssuedToken]struct{}, len(tokens))
		for index, token := range tokens {
			switch token {
			case IssuedAccessToken, IssuedRefreshToken, IssuedIDToken:
				issued[token] = struct{}{}
			default:
				return fmt.Errorf("unsupported issued token %q at index %d", token, index)
			}
		}
		endpoint.issuedTokens = issued
		return nil
	}
}

func WithIssuerOptionsCallback(callback IssuerOptionsCallback) TokenEndpointConfigOption {
	return func(endpoint *TokenEndpoint) error {
		if callback == nil {
			return errors.New("nil issuer options callback")
		}
		endpoint.issuerOptionsCallback = callback
		return nil
	}
}
