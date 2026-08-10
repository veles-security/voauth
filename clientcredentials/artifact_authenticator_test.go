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

func TestArtifactAuthenticator(t *testing.T) {
	credentials := &clientcredentials.ClientCredentials{AuthMethod: clientcredentials.ClientSecretPostAuthMethod, ClientId: "client-1", ClientSecret: "secret"}
	want := sub.NewBasePrincipal("clients", "client-1", "service")
	option := clientcredentials.WithAuthenticationMethod(clientcredentials.ClientSecretPostAuthMethod, func(_ context.Context, got *clientcredentials.ClientCredentials) (vapi.Principal, error) {
		if got != credentials {
			t.Fatal("authentication function received different credentials")
		}
		return want, nil
	})
	a, err := clientcredentials.NewArtifactAuthenticator(clientcredentials.WithArtifactAuthenticatorRuntimeOptions(option))
	if err != nil {
		t.Fatal(err)
	}
	got, err := a.AuthenticateArtifact(context.Background(), credentials)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("AuthenticateArtifact() = (%#v, %v), want (%#v, nil)", got, err, want)
	}
	_, err = a.AuthenticateArtifact(context.Background(), &clientcredentials.ClientCredentials{AuthMethod: clientcredentials.PrivateKeyJwtAuthMethod})
	if !errors.Is(err, vapi.ErrUnauthenticated) {
		t.Fatalf("unconfigured method error = %v", err)
	}
}
