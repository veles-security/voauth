package tokenrequest_test

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"testing"

	"github.com/veles-security/vapi"
	"github.com/veles-security/vapi/sub"
	"github.com/veles-security/voauth/tokenrequest"
)

type tokenRequestReaderStub struct {
	artifact *tokenrequest.TokenRequest
	err      error
	order    *[]string
}

func (s *tokenRequestReaderStub) ReadArtifact(context.Context, *http.Request, ...tokenrequest.ReaderOption) (*tokenrequest.TokenRequest, error) {
	if s.order != nil {
		*s.order = append(*s.order, "read")
	}
	return s.artifact, s.err
}

type tokenRequestValidatorStub struct {
	err   error
	order *[]string
}

func (s *tokenRequestValidatorStub) Validate(context.Context, *tokenrequest.TokenRequest, ...tokenrequest.ValidatorOption) error {
	if s.order != nil {
		*s.order = append(*s.order, "validate")
	}
	return s.err
}

type tokenRequestResolverStub struct {
	principal vapi.Principal
	err       error
	order     *[]string
}

func (s *tokenRequestResolverStub) Resolve(context.Context, *tokenrequest.TokenRequest, ...tokenrequest.ResolverOption) (vapi.Principal, error) {
	if s.order != nil {
		*s.order = append(*s.order, "resolve")
	}
	return s.principal, s.err
}

func TestAuthenticator_Authenticate(t *testing.T) {
	requestArtifact := &tokenrequest.TokenRequest{GrantType: tokenrequest.ClientCredentialsGrantType}
	want := sub.NewBasePrincipal("clients", "client-1", "service")
	failure := vapi.NewErrorCategory(vapi.ErrUnauthenticated, errors.New("failure"))
	assertAuthenticated := func(t *testing.T, got vapi.Principal, err error) {
		if err != nil || got != want {
			t.Fatalf("Authenticate() = (%#v, %v), want (%#v, nil)", got, err, want)
		}
	}
	assertUnauthenticated := func(t *testing.T, got vapi.Principal, err error) {
		if got != nil || !errors.Is(err, vapi.ErrUnauthenticated) {
			t.Fatalf("Authenticate() = (%#v, %v), want (nil, %v)", got, err, vapi.ErrUnauthenticated)
		}
	}
	assertMisconfigured := func(t *testing.T, got vapi.Principal, err error) {
		if got != nil || !errors.Is(err, vapi.ErrMisconfigured) {
			t.Fatalf("Authenticate() = (%#v, %v), want (nil, %v)", got, err, vapi.ErrMisconfigured)
		}
	}

	order := []string{}
	valid, err := tokenrequest.NewAuthenticator(
		tokenrequest.WithAuthenticatorReader(&tokenRequestReaderStub{artifact: requestArtifact, order: &order}),
		tokenrequest.WithAuthenticatorValidator(&tokenRequestValidatorStub{order: &order}),
		tokenrequest.WithAuthenticatorResolver(&tokenRequestResolverStub{principal: want, order: &order}),
	)
	if err != nil {
		t.Fatal(err)
	}
	readFails, _ := tokenrequest.NewAuthenticator(
		tokenrequest.WithAuthenticatorReader(&tokenRequestReaderStub{err: failure}),
		tokenrequest.WithAuthenticatorValidator(&tokenRequestValidatorStub{}),
		tokenrequest.WithAuthenticatorResolver(&tokenRequestResolverStub{principal: want}),
	)
	validateFails, _ := tokenrequest.NewAuthenticator(
		tokenrequest.WithAuthenticatorReader(&tokenRequestReaderStub{artifact: requestArtifact}),
		tokenrequest.WithAuthenticatorValidator(&tokenRequestValidatorStub{err: failure}),
		tokenrequest.WithAuthenticatorResolver(&tokenRequestResolverStub{principal: want}),
	)
	resolveFails, _ := tokenrequest.NewAuthenticator(
		tokenrequest.WithAuthenticatorReader(&tokenRequestReaderStub{artifact: requestArtifact}),
		tokenrequest.WithAuthenticatorValidator(&tokenRequestValidatorStub{}),
		tokenrequest.WithAuthenticatorResolver(&tokenRequestResolverStub{err: failure}),
	)
	resolveNil, _ := tokenrequest.NewAuthenticator(
		tokenrequest.WithAuthenticatorReader(&tokenRequestReaderStub{artifact: requestArtifact}),
		tokenrequest.WithAuthenticatorValidator(&tokenRequestValidatorStub{}),
		tokenrequest.WithAuthenticatorResolver(&tokenRequestResolverStub{}),
	)

	tests := []struct {
		name          string
		authenticator *tokenrequest.Authenticator
		assert        func(*testing.T, vapi.Principal, error)
	}{
		{name: "reads validates and resolves", authenticator: valid, assert: assertAuthenticated},
		{name: "read failure", authenticator: readFails, assert: assertUnauthenticated},
		{name: "validation failure", authenticator: validateFails, assert: assertUnauthenticated},
		{name: "resolution failure", authenticator: resolveFails, assert: assertUnauthenticated},
		{name: "nil principal", authenticator: resolveNil, assert: assertUnauthenticated},
		{name: "nil receiver", assert: assertMisconfigured},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			order = order[:0]
			got, gotErr := tt.authenticator.Authenticate(context.Background(), &http.Request{})
			tt.assert(t, got, gotErr)
			if tt.name == "reads validates and resolves" && !reflect.DeepEqual(order, []string{"read", "validate", "resolve"}) {
				t.Errorf("authentication order = %#v", order)
			}
		})
	}
}

func TestNewAuthenticator(t *testing.T) {
	assertCreated := func(t *testing.T, got *tokenrequest.Authenticator, err error) {
		if err != nil || got == nil {
			t.Fatalf("NewAuthenticator() = (%#v, %v), want authenticator", got, err)
		}
	}
	assertMisconfigured := func(t *testing.T, got *tokenrequest.Authenticator, err error) {
		if got != nil || !errors.Is(err, vapi.ErrMisconfigured) {
			t.Fatalf("NewAuthenticator() = (%#v, %v), want (nil, %v)", got, err, vapi.ErrMisconfigured)
		}
	}
	tests := []struct {
		name    string
		options []tokenrequest.AuthenticatorConfigOption
		assert  func(*testing.T, *tokenrequest.Authenticator, error)
	}{
		{name: "defaults", assert: assertCreated},
		{name: "reader options", options: []tokenrequest.AuthenticatorConfigOption{tokenrequest.WithAuthenticatorReaderOptions()}, assert: assertCreated},
		{name: "validator options", options: []tokenrequest.AuthenticatorConfigOption{tokenrequest.WithAuthenticatorValidatorOptions()}, assert: assertCreated},
		{name: "resolver options", options: []tokenrequest.AuthenticatorConfigOption{tokenrequest.WithAuthenticatorResolverOptions()}, assert: assertCreated},
		{name: "nil option", options: []tokenrequest.AuthenticatorConfigOption{nil}, assert: assertMisconfigured},
		{name: "nil reader", options: []tokenrequest.AuthenticatorConfigOption{tokenrequest.WithAuthenticatorReader(nil)}, assert: assertMisconfigured},
		{name: "nil validator", options: []tokenrequest.AuthenticatorConfigOption{tokenrequest.WithAuthenticatorValidator(nil)}, assert: assertMisconfigured},
		{name: "nil resolver", options: []tokenrequest.AuthenticatorConfigOption{tokenrequest.WithAuthenticatorResolver(nil)}, assert: assertMisconfigured},
		{name: "invalid reader options", options: []tokenrequest.AuthenticatorConfigOption{tokenrequest.WithAuthenticatorReaderOptions(nil)}, assert: assertMisconfigured},
		{name: "invalid validator options", options: []tokenrequest.AuthenticatorConfigOption{tokenrequest.WithAuthenticatorValidatorOptions(nil)}, assert: assertMisconfigured},
		{name: "invalid resolver options", options: []tokenrequest.AuthenticatorConfigOption{tokenrequest.WithAuthenticatorResolverOptions(nil)}, assert: assertMisconfigured},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := tokenrequest.NewAuthenticator(tt.options...)
			tt.assert(t, got, gotErr)
		})
	}
}
