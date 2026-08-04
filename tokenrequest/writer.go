package tokenrequest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

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
	if writer.clientCredentialsEncoder == nil {
		encoder, err := clientcredentials.NewWriter()
		if err != nil {
			return nil, err
		}
		writer.clientCredentialsEncoder = encoder
	}
	return writer, nil
}

// WriteArtifact implements [vapi.Writer].
func (w *Writer) WriteArtifact(ctx context.Context, carrierWriter *http.Request, artifact *TokenRequest, options ...WriterOption) error {
	if w == nil || w.clientCredentialsEncoder == nil {
		return vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("cannot write token request with nil client credentials encoder"))
	}
	if carrierWriter == nil {
		return vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("cannot write token request to nil request"))
	}
	if artifact == nil {
		return vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("cannot write nil token request"))
	}
	if artifact.GrantType == RefreshTokenGrantType && artifact.RefreshToken != nil && w.tokenEncoder == nil {
		return vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("cannot write refresh token with nil token encoder"))
	}
	if (artifact.GrantType == JwtBearerGrantType || artifact.GrantType == Saml2BearerGrantType) && artifact.Assertion != nil && w.assertionTokenEncoder == nil {
		return vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("cannot write bearer assertion with nil assertion token encoder"))
	}

	next := w.writeArtifact
	for index := len(options) - 1; index >= 0; index-- {
		option := options[index]
		if option == nil {
			return vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("nil writer option at index %d", index))
		}
		wrapped := option(next)
		if wrapped == nil {
			return vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("writer option at index %d returned nil WriteFunc", index))
		}
		next = wrapped
	}

	return next(ctx, carrierWriter, artifact)
}

func (w *Writer) writeArtifact(ctx context.Context, carrier *http.Request, artifact *TokenRequest) error {
	if err := w.clientCredentialsEncoder.WriteArtifact(ctx, carrier, &artifact.ClientCredentials); err != nil {
		return fmt.Errorf("write client credentials: %w", err)
	}

	form := url.Values{}
	if carrier.Body != nil {
		body, err := io.ReadAll(carrier.Body)
		if err != nil {
			return vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("read client credentials form: %w", err))
		}
		form, err = url.ParseQuery(string(body))
		if err != nil {
			return vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("parse client credentials form: %w", err))
		}
	}
	form.Set("grant_type", artifact.GrantType)

	switch artifact.GrantType {
	case AuthorizationCodeGrantType:
		if artifact.Code != "" {
			form.Set("code", artifact.Code)
		}
		if artifact.RedirectUri != "" {
			form.Set("redirect_uri", artifact.RedirectUri)
		}
		if artifact.CodeVerifier != "" {
			form.Set("code_verifier", artifact.CodeVerifier)
		}
	case PasswordGrantType:
		if artifact.Username != "" {
			form.Set("username", artifact.Username)
		}
		if artifact.Password != "" {
			form.Set("password", artifact.Password)
		}
		if artifact.Scope != "" {
			form.Set("scope", artifact.Scope)
		}
	case ClientCredentialsGrantType:
		if artifact.Scope != "" {
			form.Set("scope", artifact.Scope)
		}
	case RefreshTokenGrantType:
		if artifact.RefreshToken != nil {
			encoded, encodeErr := w.tokenEncoder.EncodeAnyToken(ctx, artifact.RefreshToken)
			if encodeErr != nil {
				return vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("encode refresh token: %w", encodeErr))
			}
			form.Set("refresh_token", string(encoded))
		}
		if artifact.Scope != "" {
			form.Set("scope", artifact.Scope)
		}
	case DeviceCodeGrantType:
		if artifact.DeviceCode != "" {
			form.Set("device_code", artifact.DeviceCode)
		}
	case JwtBearerGrantType, Saml2BearerGrantType:
		if artifact.Assertion != nil {
			encoded, encodeErr := w.assertionTokenEncoder.EncodeAnyToken(ctx, artifact.Assertion)
			if encodeErr != nil {
				return vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("encode bearer assertion: %w", encodeErr))
			}
			form.Set("assertion", string(encoded))
		}
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

var _ vapi.Writer[*http.Request, *TokenRequest, WriterOption] = &Writer{}
