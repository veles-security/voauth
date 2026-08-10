package clientcredentials_test

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"testing"

	"github.com/veles-security/vapi"
	"github.com/veles-security/vapi/sub"
	"github.com/veles-security/voauth/clientcredentials"
)

type readerStub struct {
	credentials *clientcredentials.ClientCredentials
	err         error
	read        bool
}

func (r *readerStub) ReadArtifact(context.Context, *http.Request, ...clientcredentials.ReaderOption) (*clientcredentials.ClientCredentials, error) {
	r.read = true
	return r.credentials, r.err
}

type validatorStub struct {
	err       error
	validated *clientcredentials.ClientCredentials
}

func (v *validatorStub) Validate(_ context.Context, c *clientcredentials.ClientCredentials, _ ...clientcredentials.ValidatorOption) error {
	v.validated = c
	return v.err
}

type resolverStub struct {
	principal     vapi.Principal
	err           error
	authenticated *clientcredentials.ClientCredentials
}

func (a *resolverStub) Resolve(_ context.Context, c *clientcredentials.ClientCredentials, _ ...clientcredentials.ResolverOption) (vapi.Principal, error) {
	a.authenticated = c
	return a.principal, a.err
}

func TestAuthenticator_Authenticate(t *testing.T) {
	credentials := &clientcredentials.ClientCredentials{AuthMethod: clientcredentials.ClientSecretPostAuthMethod, ClientId: "client-1", ClientSecret: "secret"}
	principal := sub.NewBasePrincipal("clients", "client-1", "service")
	validationFailure, authenticationFailure := errors.New("invalid shape"), errors.New("invalid secret")

	tests := []struct {
		name      string
		reader    *readerStub
		validator *validatorStub
		resolver  *resolverStub
		want      vapi.Principal
		wantError error
	}{
		{name: "reader validator resolver", reader: &readerStub{credentials: credentials}, validator: &validatorStub{}, resolver: &resolverStub{principal: principal}, want: principal},
		{name: "not applicable", reader: &readerStub{err: vapi.ErrNotApplicable}, validator: &validatorStub{}, resolver: &resolverStub{}, wantError: vapi.ErrNotApplicable},
		{name: "reader failure", reader: &readerStub{err: vapi.ErrMalformed}, validator: &validatorStub{}, resolver: &resolverStub{}, wantError: vapi.ErrUnauthenticated},
		{name: "validation failure", reader: &readerStub{credentials: credentials}, validator: &validatorStub{err: validationFailure}, resolver: &resolverStub{}, wantError: vapi.ErrUnauthenticated},
		{name: "artifact authentication failure", reader: &readerStub{credentials: credentials}, validator: &validatorStub{}, resolver: &resolverStub{err: authenticationFailure}, wantError: vapi.ErrUnauthenticated},
		{name: "nil principal", reader: &readerStub{credentials: credentials}, validator: &validatorStub{}, resolver: &resolverStub{}, wantError: vapi.ErrUnauthenticated},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := clientcredentials.NewAuthenticator(clientcredentials.WithAuthenticatorReader(tt.reader), clientcredentials.WithAuthenticatorValidator(tt.validator), clientcredentials.WithAuthenticatorResolver(tt.resolver))
			if err != nil {
				t.Fatal(err)
			}
			got, gotErr := a.Authenticate(context.Background(), &http.Request{})
			if !reflect.DeepEqual(got, tt.want) || !errors.Is(gotErr, tt.wantError) {
				t.Fatalf("Authenticate() = (%#v, %v), want (%#v, %v)", got, gotErr, tt.want, tt.wantError)
			}
			if tt.wantError == nil && (tt.validator.validated != credentials || tt.resolver.authenticated != credentials) {
				t.Fatal("collaborators did not receive the read artifact")
			}
		})
	}
}

func TestNewAuthenticator(t *testing.T) {
	if got, err := clientcredentials.NewAuthenticator(); err != nil || got == nil {
		t.Fatalf("NewAuthenticator() = (%#v, %v)", got, err)
	}
	for name, option := range map[string]clientcredentials.AuthenticatorConfigOption{
		"nil option":    nil,
		"nil reader":    clientcredentials.WithAuthenticatorReader(nil),
		"nil validator": clientcredentials.WithAuthenticatorValidator(nil),
		"nil resolver":  clientcredentials.WithAuthenticatorResolver(nil),
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := clientcredentials.NewAuthenticator(option); got != nil || !errors.Is(err, vapi.ErrMisconfigured) {
				t.Fatalf("NewAuthenticator() = (%#v, %v)", got, err)
			}
		})
	}
}
