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

func TestResolver(t *testing.T) {
	credentials := &clientcredentials.ClientCredentials{AuthMethod: clientcredentials.ClientSecretPostAuthMethod, ClientId: "client-1", ClientSecret: "secret"}
	want := sub.NewBasePrincipal("clients", "client-1", "service")
	option := clientcredentials.WithResolverAuthenticationMethod(clientcredentials.ClientSecretPostAuthMethod, func(_ context.Context, got *clientcredentials.ClientCredentials) (vapi.Principal, error) {
		if got != credentials {
			t.Fatal("authentication function received different credentials")
		}
		return want, nil
	})
	a, err := clientcredentials.NewResolver(clientcredentials.WithResolverRuntimeOptions(option))
	if err != nil {
		t.Fatal(err)
	}
	got, err := a.Resolve(context.Background(), credentials)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("Resolve() = (%#v, %v), want (%#v, nil)", got, err, want)
	}
	_, err = a.Resolve(context.Background(), &clientcredentials.ClientCredentials{AuthMethod: clientcredentials.PrivateKeyJwtAuthMethod})
	if !errors.Is(err, vapi.ErrUnauthenticated) {
		t.Fatalf("unconfigured method error = %v", err)
	}
}
