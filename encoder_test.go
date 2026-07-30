package velesoauth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/veles-security/vapi"
	velesoauth "github.com/veles-security/voauth"
)

func issueToken(t *testing.T) *velesoauth.JwtToken {
	keyRSA2048, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	issuer := velesoauth.NewJwtIssuer(velesoauth.WithJwtIssuer("safe"), velesoauth.NewJwtSigner(keyRSA2048, vapi.SigAlgRS256))
	issuedToken, err := issuer.Issue(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return issuedToken
}

func TestJwtEncoder_Encode(t *testing.T) {
	issuedToken := issueToken(t)
	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		token   *velesoauth.JwtToken
		want    []byte
		wantErr bool
	}{
		{
			name:  "minimal",
			token: &velesoauth.JwtToken{Header: map[string]string{"alg": "none"}, Claims: map[string]any{"sub": "me"}},
			want:  []byte("eyJhbGciOiJub25lIn0.eyJzdWIiOiJtZSJ9."),
		},
		{
			name:  "issued",
			token: issuedToken,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j := velesoauth.NewJwtEncoder()
			got, gotErr := j.Encode(context.Background(), tt.token)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("Encode() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("Encode() succeeded unexpectedly")
			}
			if tt.want != nil {
				if string(tt.want) != string(got) {
					t.Errorf("Encode() = %v, want %v", string(got), string(tt.want))
				}
			}
		})
	}
}
