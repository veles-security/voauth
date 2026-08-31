package presets

import (
	"context"
	"errors"
	"fmt"

	"github.com/veles-security/vapi"
	"github.com/veles-security/vcrypt/jws"
	"github.com/veles-security/voauth/jwt"
	"github.com/veles-security/voauth/tokenendpoint"
)

// TokenCallback prepares the issuer options for one token type.
type TokenCallback func(context.Context, vapi.ScopedPrincipal) ([]jwt.IssuerOption, error)

// TokenOption configures one token type in [Tokens].
type TokenOption func(*tokenConfig) error

type tokenConfig struct {
	issued  []tokenendpoint.IssuedToken
	access  TokenCallback
	refresh TokenCallback
	id      TokenCallback
}

// Signer attaches a signer to the endpoint's JWT issuer.
func Signer(signer vapi.Signer[jws.SignerOption, jws.JWS]) tokenendpoint.TokenEndpointConfigOption {
	return func(endpoint *tokenendpoint.TokenEndpoint) error {
		if signer == nil {
			return errors.New("nil signer")
		}
		return tokenendpoint.WithIssuerOptions(jwt.WithSigner(signer))(endpoint)
	}
}

// Tokens selects the issued token types and configures their callbacks.
func Tokens(options ...TokenOption) tokenendpoint.TokenEndpointConfigOption {
	return func(endpoint *tokenendpoint.TokenEndpoint) error {
		config := &tokenConfig{}
		for index, option := range options {
			if option == nil {
				return fmt.Errorf("nil token preset option at index %d", index)
			}
			if err := option(config); err != nil {
				return err
			}
		}
		if len(config.issued) == 0 {
			return errors.New("no token callbacks")
		}

		if err := tokenendpoint.WithIssuedTokens(config.issued...)(endpoint); err != nil {
			return err
		}
		return tokenendpoint.WithIssuerOptionsCallback(func(ctx context.Context, principal vapi.ScopedPrincipal) (tokenendpoint.IssuerOptions, error) {
			var issuerOptions tokenendpoint.IssuerOptions
			var err error
			if config.access != nil {
				issuerOptions.AccessToken, err = config.access(ctx, principal)
				if err != nil {
					return tokenendpoint.IssuerOptions{}, fmt.Errorf("prepare access token: %w", err)
				}
			}
			if config.refresh != nil {
				issuerOptions.RefreshToken, err = config.refresh(ctx, principal)
				if err != nil {
					return tokenendpoint.IssuerOptions{}, fmt.Errorf("prepare refresh token: %w", err)
				}
			}
			if config.id != nil {
				issuerOptions.IDToken, err = config.id(ctx, principal)
				if err != nil {
					return tokenendpoint.IssuerOptions{}, fmt.Errorf("prepare ID token: %w", err)
				}
			}
			return issuerOptions, nil
		})(endpoint)
	}
}

// AccessToken enables access-token issuance and sets its callback.
func AccessToken(callback TokenCallback) TokenOption {
	return func(config *tokenConfig) error {
		if callback == nil {
			return errors.New("nil access token callback")
		}
		config.issued = append(config.issued, tokenendpoint.IssuedAccessToken)
		config.access = callback
		return nil
	}
}

// RefreshToken enables refresh-token issuance and sets its callback.
func RefreshToken(callback TokenCallback) TokenOption {
	return func(config *tokenConfig) error {
		if callback == nil {
			return errors.New("nil refresh token callback")
		}
		config.issued = append(config.issued, tokenendpoint.IssuedRefreshToken)
		config.refresh = callback
		return nil
	}
}

// IDToken enables ID-token issuance and sets its callback.
func IDToken(callback TokenCallback) TokenOption {
	return func(config *tokenConfig) error {
		if callback == nil {
			return errors.New("nil ID token callback")
		}
		config.issued = append(config.issued, tokenendpoint.IssuedIDToken)
		config.id = callback
		return nil
	}
}
