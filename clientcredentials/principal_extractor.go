package clientcredentials

import (
	"context"
	"errors"
	"fmt"

	"github.com/veles-security/vapi"
)

type PrincipalExtractor struct {
	authCallback AuthCallback
}

type PrincipalExtractorConfigOption func(*PrincipalExtractor) error

type AuthCallback func(ctx context.Context, credentials *ClientCredentials) (vapi.Principal, error)

type ExtractPrincipalFunc func(ctx context.Context, credentials *ClientCredentials) (vapi.Principal, error)

type PrincipalExtractorOption func(next ExtractPrincipalFunc) ExtractPrincipalFunc

func NewPrincipalExtractor(configOptions ...PrincipalExtractorConfigOption) (*PrincipalExtractor, error) {
	extractor := &PrincipalExtractor{}
	for _, option := range configOptions {
		if option == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("nil principal extractor config option"))
		}
		if err := option(extractor); err != nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, err)
		}
	}
	if extractor.authCallback == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("nil client credentials auth callback"))
	}
	return extractor, nil
}

// ExtractPrincipal implements [vapi.PrincipalExtractor].
func (e *PrincipalExtractor) ExtractPrincipal(ctx context.Context, credentials *ClientCredentials, options ...PrincipalExtractorOption) (vapi.Principal, error) {
	if e == nil || e.authCallback == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, errors.New("cannot extract principal with invalid client credentials principal extractor configuration"))
	}
	if credentials == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("cannot extract principal from nil client credentials"))
	}

	next := e.extractPrincipal
	for index := len(options) - 1; index >= 0; index-- {
		option := options[index]
		if option == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("nil principal extractor option at index %d", index))
		}
		wrapped := option(next)
		if wrapped == nil {
			return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("principal extractor option at index %d returned nil ExtractPrincipalFunc", index))
		}
		next = wrapped
	}
	return next(ctx, credentials)
}

func (e *PrincipalExtractor) extractPrincipal(ctx context.Context, credentials *ClientCredentials) (vapi.Principal, error) {
	principal, err := e.authCallback(ctx, credentials)
	if err != nil {
		return nil, vapi.NewErrorCategory(vapi.ErrUnauthenticated, fmt.Errorf("authenticate client credentials: %w", err))
	}
	if principal == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrUnauthenticated, errors.New("client credentials auth callback returned nil principal"))
	}
	return principal, nil
}

var _ vapi.PrincipalExtractor[*ClientCredentials, PrincipalExtractorOption] = &PrincipalExtractor{}
