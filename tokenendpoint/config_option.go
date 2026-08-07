package tokenendpoint

import (
	"errors"
	"fmt"
	"net/http"
	"slices"

	"github.com/veles-security/vapi"
	"github.com/veles-security/voauth/jwt"
	"github.com/veles-security/voauth/tokenrequest"
	"github.com/veles-security/voauth/tokenresponse"
)

// WithTokenRequestReaderOptions configures the token request reader constructed by the endpoint.
func WithTokenRequestReaderOptions(options ...tokenrequest.ReaderConfigOption) TokenEndpointConfigOption {
	return func(endpoint *TokenEndpoint) error {
		endpoint.requestReaderOptions = append(endpoint.requestReaderOptions, slices.Clone(options)...)
		return nil
	}
}

// WithTokenRequestAuthenticator binds the token request authenticator.
func WithTokenRequestAuthenticator(authenticator vapi.Authenticator[*tokenrequest.TokenRequest]) TokenEndpointConfigOption {
	return func(endpoint *TokenEndpoint) error {
		if authenticator == nil {
			return errors.New("nil token request authenticator")
		}
		endpoint.requestAuthenticator = authenticator
		return nil
	}
}

// WithTokenRequestAuthenticatorOptions constructs and binds the token request authenticator.
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

// WithIssuer binds the JWT issuer.
func WithIssuer(issuer vapi.Issuer[jwt.IssuerOption, *jwt.Token]) TokenEndpointConfigOption {
	return func(endpoint *TokenEndpoint) error {
		if issuer == nil {
			return errors.New("nil issuer")
		}
		endpoint.issuer = issuer
		return nil
	}
}

// WithIssuerOptions constructs and binds the JWT issuer.
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

// WithTokenResponseWriter binds the token response writer.
func WithTokenResponseWriter(writer vapi.Writer[http.ResponseWriter, *tokenresponse.TokenResponse, tokenresponse.WriterOption]) TokenEndpointConfigOption {
	return func(endpoint *TokenEndpoint) error {
		if writer == nil {
			return errors.New("nil token response writer")
		}
		endpoint.responseWriter = writer
		return nil
	}
}

// WithTokenResponseWriterOptions constructs and binds the token response writer.
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

// WithIssuedTokens configures which token fields are issued and returned.
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

// WithIssuerOptionsCallback configures application policy that prepares the
// token-specific issue options from the scoped principal and token request.
func WithIssuerOptionsCallback(callback IssuerOptionsCallback) TokenEndpointConfigOption {
	return func(endpoint *TokenEndpoint) error {
		if callback == nil {
			return errors.New("nil issuer options callback")
		}
		endpoint.issuerOptionsCallback = callback
		return nil
	}
}
