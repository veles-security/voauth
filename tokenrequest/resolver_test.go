package tokenrequest_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/veles-security/vapi"
	"github.com/veles-security/vapi/sub"
	"github.com/veles-security/voauth/clientcredentials"
	"github.com/veles-security/voauth/tokenrequest"
)

type clientResolverStub struct {
	principal vapi.Principal
	err       error
	order     *[]string
}

func (s *clientResolverStub) Resolve(context.Context, *clientcredentials.ClientCredentials, ...clientcredentials.ResolverOption) (vapi.Principal, error) {
	if s.order != nil {
		*s.order = append(*s.order, "client")
	}
	return s.principal, s.err
}

func TestResolver_Resolve(t *testing.T) {
	request := &tokenrequest.TokenRequest{GrantType: tokenrequest.PasswordGrantType}
	clientPrincipal := sub.NewBasePrincipal("clients", "client-1", "service")
	want := sub.NewBasePrincipal("issuer", "user-1", "user")
	failure := errors.New("failure")
	order := []string{}
	callback := tokenrequest.AuthCallback(func(context.Context, *tokenrequest.TokenRequest, vapi.Principal) (vapi.Principal, error) {
		order = append(order, "grant")
		return want, nil
	})
	valid, err := tokenrequest.NewResolver(
		tokenrequest.WithResolverClientResolver(&clientResolverStub{principal: clientPrincipal, order: &order}),
		tokenrequest.WithResolverAuthCallback(tokenrequest.PasswordGrantType, callback),
	)
	if err != nil {
		t.Fatal(err)
	}
	clientOnly, _ := tokenrequest.NewResolver(tokenrequest.WithResolverClientResolver(&clientResolverStub{principal: clientPrincipal}))
	clientFails, _ := tokenrequest.NewResolver(tokenrequest.WithResolverClientResolver(&clientResolverStub{err: failure}), tokenrequest.WithResolverAuthCallback(tokenrequest.PasswordGrantType, callback))
	callbackFails, _ := tokenrequest.NewResolver(tokenrequest.WithResolverClientResolver(&clientResolverStub{principal: clientPrincipal}), tokenrequest.WithResolverAuthCallback(tokenrequest.PasswordGrantType, func(context.Context, *tokenrequest.TokenRequest, vapi.Principal) (vapi.Principal, error) {
		return nil, failure
	}))
	callbackNil, _ := tokenrequest.NewResolver(tokenrequest.WithResolverClientResolver(&clientResolverStub{principal: clientPrincipal}), tokenrequest.WithResolverAuthCallback(tokenrequest.PasswordGrantType, func(context.Context, *tokenrequest.TokenRequest, vapi.Principal) (vapi.Principal, error) {
		return nil, nil
	}))

	assertPrincipal := func(expected vapi.Principal) func(*testing.T, vapi.Principal, error) {
		return func(t *testing.T, got vapi.Principal, err error) {
			if err != nil || !reflect.DeepEqual(got, expected) {
				t.Fatalf("Resolve() = (%#v, %v), want (%#v, nil)", got, err, expected)
			}
		}
	}
	assertError := func(category error) func(*testing.T, vapi.Principal, error) {
		return func(t *testing.T, got vapi.Principal, err error) {
			if got != nil || !errors.Is(err, category) {
				t.Fatalf("Resolve() = (%#v, %v), want category %v", got, err, category)
			}
		}
	}
	tests := []struct {
		name     string
		resolver *tokenrequest.Resolver
		artifact *tokenrequest.TokenRequest
		options  []tokenrequest.ResolverOption
		assert   func(*testing.T, vapi.Principal, error)
	}{
		{name: "client then grant", resolver: valid, artifact: request, assert: assertPrincipal(want)},
		{name: "client credentials principal", resolver: clientOnly, artifact: &tokenrequest.TokenRequest{GrantType: tokenrequest.ClientCredentialsGrantType}, assert: assertPrincipal(clientPrincipal)},
		{name: "missing callback", resolver: clientOnly, artifact: request, assert: assertError(vapi.ErrUnauthenticated)},
		{name: "client failure", resolver: clientFails, artifact: request, assert: assertError(failure)},
		{name: "callback failure", resolver: callbackFails, artifact: request, assert: assertError(failure)},
		{name: "callback returns nil", resolver: callbackNil, artifact: request, assert: assertError(vapi.ErrUnauthenticated)},
		{name: "nil artifact", resolver: valid, assert: assertError(vapi.ErrMalformed)},
		{name: "nil receiver", artifact: request, assert: assertError(vapi.ErrMisconfigured)},
		{name: "nil runtime option", resolver: valid, artifact: request, options: []tokenrequest.ResolverOption{nil}, assert: assertError(vapi.ErrMisconfigured)},
		{name: "nil decorator", resolver: valid, artifact: request, options: []tokenrequest.ResolverOption{func(tokenrequest.ResolveFunc) tokenrequest.ResolveFunc { return nil }}, assert: assertError(vapi.ErrMisconfigured)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			order = order[:0]
			got, gotErr := tt.resolver.Resolve(context.Background(), tt.artifact, tt.options...)
			tt.assert(t, got, gotErr)
			if tt.name == "client then grant" && !reflect.DeepEqual(order, []string{"client", "grant"}) {
				t.Errorf("resolution order = %#v", order)
			}
		})
	}
}

func TestNewResolver(t *testing.T) {
	callback := clientcredentials.ResolveFunc(func(context.Context, *clientcredentials.ClientCredentials) (vapi.Principal, error) {
		return sub.NewBasePrincipal("clients", "client-1", "service"), nil
	})
	tests := []struct {
		name    string
		options []tokenrequest.ResolverConfigOption
		wantErr bool
	}{
		{name: "defaults"},
		{name: "client resolver options", options: []tokenrequest.ResolverConfigOption{tokenrequest.WithResolverClientResolverOptions(clientcredentials.WithResolverRuntimeOptions(clientcredentials.WithResolverAuthenticationMethod(clientcredentials.ClientSecretPostAuthMethod, callback)))}},
		{name: "nil option", options: []tokenrequest.ResolverConfigOption{nil}, wantErr: true},
		{name: "empty grant type", options: []tokenrequest.ResolverConfigOption{tokenrequest.WithResolverAuthCallback("", func(context.Context, *tokenrequest.TokenRequest, vapi.Principal) (vapi.Principal, error) {
			return nil, nil
		})}, wantErr: true},
		{name: "nil callback", options: []tokenrequest.ResolverConfigOption{tokenrequest.WithResolverAuthCallback(tokenrequest.PasswordGrantType, nil)}, wantErr: true},
		{name: "nil client resolver", options: []tokenrequest.ResolverConfigOption{tokenrequest.WithResolverClientResolver(nil)}, wantErr: true},
		{name: "invalid client resolver options", options: []tokenrequest.ResolverConfigOption{tokenrequest.WithResolverClientResolverOptions(nil)}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tokenrequest.NewResolver(tt.options...)
			if tt.wantErr {
				if got != nil || !errors.Is(err, vapi.ErrMisconfigured) {
					t.Fatalf("NewResolver() = (%#v, %v), want misconfigured", got, err)
				}
				return
			}
			if got == nil || err != nil {
				t.Fatalf("NewResolver() = (%#v, %v), want resolver", got, err)
			}
		})
	}
}
