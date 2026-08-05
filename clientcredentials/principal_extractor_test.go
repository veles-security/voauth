package clientcredentials_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/veles-security/vapi"
	"github.com/veles-security/vapi/sub"
	"github.com/veles-security/voauth/clientcredentials"
)

func TestPrincipalExtractor_ExtractPrincipal(t *testing.T) {
	wantPrincipal := sub.NewBasePrincipal("clients", "client-1", "service")
	wantCredentials := &clientcredentials.ClientCredentials{
		AuthMethod:   clientcredentials.ClientSecretBasicAuthMethod,
		ClientId:     "client-1",
		ClientSecret: "secret",
	}
	callbackFailure := errors.New("invalid client secret")
	assertExtracted := func(t *testing.T, got vapi.Principal, err error) {
		if err != nil {
			t.Fatalf("ExtractPrincipal() failed: %v", err)
		}
		if !reflect.DeepEqual(got, wantPrincipal) {
			t.Errorf("ExtractPrincipal() principal = %#v, want %#v", got, wantPrincipal)
		}
	}
	assertUnauthenticated := func(t *testing.T, got vapi.Principal, err error) {
		if got != nil || !errors.Is(err, vapi.ErrUnauthenticated) {
			t.Fatalf("ExtractPrincipal() = (%#v, %v), want (nil, %v)", got, err, vapi.ErrUnauthenticated)
		}
	}
	assertMalformed := func(t *testing.T, got vapi.Principal, err error) {
		if got != nil || !errors.Is(err, vapi.ErrMalformed) {
			t.Fatalf("ExtractPrincipal() = (%#v, %v), want (nil, %v)", got, err, vapi.ErrMalformed)
		}
	}
	assertMisconfigured := func(t *testing.T, got vapi.Principal, err error) {
		if got != nil || !errors.Is(err, vapi.ErrMisconfigured) {
			t.Fatalf("ExtractPrincipal() = (%#v, %v), want (nil, %v)", got, err, vapi.ErrMisconfigured)
		}
	}

	validCallback := clientcredentials.AuthCallback(func(_ context.Context, credentials *clientcredentials.ClientCredentials) (vapi.Principal, error) {
		if !reflect.DeepEqual(credentials, wantCredentials) {
			t.Errorf("callback credentials = %#v, want %#v", credentials, wantCredentials)
		}
		return wantPrincipal, nil
	})
	validExtractor, err := clientcredentials.NewPrincipalExtractor(clientcredentials.WithAuthCallback(validCallback))
	if err != nil {
		t.Fatalf("NewPrincipalExtractor() failed: %v", err)
	}
	failingExtractor, err := clientcredentials.NewPrincipalExtractor(clientcredentials.WithAuthCallback(
		func(context.Context, *clientcredentials.ClientCredentials) (vapi.Principal, error) {
			return nil, callbackFailure
		},
	))
	if err != nil {
		t.Fatalf("NewPrincipalExtractor() failed: %v", err)
	}
	nilPrincipalExtractor, err := clientcredentials.NewPrincipalExtractor(clientcredentials.WithAuthCallback(
		func(context.Context, *clientcredentials.ClientCredentials) (vapi.Principal, error) { return nil, nil },
	))
	if err != nil {
		t.Fatalf("NewPrincipalExtractor() failed: %v", err)
	}

	order := make([]string, 0, 4)
	first := func(next clientcredentials.ExtractPrincipalFunc) clientcredentials.ExtractPrincipalFunc {
		return func(ctx context.Context, credentials *clientcredentials.ClientCredentials) (vapi.Principal, error) {
			order = append(order, "first-before")
			principal, err := next(ctx, credentials)
			order = append(order, "first-after")
			return principal, err
		}
	}
	second := func(next clientcredentials.ExtractPrincipalFunc) clientcredentials.ExtractPrincipalFunc {
		return func(ctx context.Context, credentials *clientcredentials.ClientCredentials) (vapi.Principal, error) {
			order = append(order, "second-before")
			principal, err := next(ctx, credentials)
			order = append(order, "second-after")
			return principal, err
		}
	}

	tests := []struct {
		name        string
		extractor   *clientcredentials.PrincipalExtractor
		credentials *clientcredentials.ClientCredentials
		options     []clientcredentials.PrincipalExtractorOption
		assert      func(t *testing.T, got vapi.Principal, err error)
	}{
		{name: "client secret", extractor: validExtractor, credentials: wantCredentials, assert: assertExtracted},
		{name: "decorators", extractor: validExtractor, credentials: wantCredentials, options: []clientcredentials.PrincipalExtractorOption{first, second}, assert: assertExtracted},
		{name: "callback failure", extractor: failingExtractor, credentials: wantCredentials, assert: assertUnauthenticated},
		{name: "callback returns nil principal", extractor: nilPrincipalExtractor, credentials: wantCredentials, assert: assertUnauthenticated},
		{name: "nil credentials", extractor: validExtractor, credentials: nil, assert: assertMalformed},
		{name: "nil receiver", extractor: nil, credentials: wantCredentials, assert: assertMisconfigured},
		{name: "nil option", extractor: validExtractor, credentials: wantCredentials, options: []clientcredentials.PrincipalExtractorOption{nil}, assert: assertMisconfigured},
		{name: "nil decorator result", extractor: validExtractor, credentials: wantCredentials, options: []clientcredentials.PrincipalExtractorOption{func(clientcredentials.ExtractPrincipalFunc) clientcredentials.ExtractPrincipalFunc { return nil }}, assert: assertMisconfigured},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			order = order[:0]
			got, gotErr := tt.extractor.ExtractPrincipal(context.Background(), tt.credentials, tt.options...)
			tt.assert(t, got, gotErr)
			if tt.name == "decorators" {
				wantOrder := []string{"first-before", "second-before", "second-after", "first-after"}
				if !reflect.DeepEqual(order, wantOrder) {
					t.Errorf("decorator order = %#v, want %#v", order, wantOrder)
				}
			}
		})
	}
}

func TestNewPrincipalExtractor(t *testing.T) {
	callback := clientcredentials.AuthCallback(func(context.Context, *clientcredentials.ClientCredentials) (vapi.Principal, error) {
		return sub.NewBasePrincipal("clients", "client-1", "service"), nil
	})
	assertCreated := func(t *testing.T, got *clientcredentials.PrincipalExtractor, err error) {
		if err != nil || got == nil {
			t.Fatalf("NewPrincipalExtractor() = (%#v, %v), want non-nil extractor", got, err)
		}
	}
	assertMisconfigured := func(t *testing.T, got *clientcredentials.PrincipalExtractor, err error) {
		if got != nil || !errors.Is(err, vapi.ErrMisconfigured) {
			t.Fatalf("NewPrincipalExtractor() = (%#v, %v), want (nil, %v)", got, err, vapi.ErrMisconfigured)
		}
	}
	tests := []struct {
		name    string
		options []clientcredentials.PrincipalExtractorConfigOption
		assert  func(t *testing.T, got *clientcredentials.PrincipalExtractor, err error)
	}{
		{name: "auth callback", options: []clientcredentials.PrincipalExtractorConfigOption{clientcredentials.WithAuthCallback(callback)}, assert: assertCreated},
		{name: "missing callback", assert: assertMisconfigured},
		{name: "nil config option", options: []clientcredentials.PrincipalExtractorConfigOption{nil}, assert: assertMisconfigured},
		{name: "nil callback", options: []clientcredentials.PrincipalExtractorConfigOption{clientcredentials.WithAuthCallback(nil)}, assert: assertMisconfigured},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := clientcredentials.NewPrincipalExtractor(tt.options...)
			tt.assert(t, got, gotErr)
		})
	}
}
