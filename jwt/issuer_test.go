package jwt

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/veles-security/vapi"
	"github.com/veles-security/vapi/sig"
	"github.com/veles-security/voauth/internal/testkeys"
)

func TestIssuer_Issue(t *testing.T) {
	privateKey := testkeys.Private(t, testkeys.RSA2048).(*rsa.PrivateKey)
	signer := &sig.Signer{Kid: "test-key", Alg: sig.SigAlgRS256, Key: privateKey}

	tests := []struct {
		name       string
		issuer     *Issuer
		options    []JwtIssuerOption
		assertions func(*testing.T, *Token, error)
	}{
		{
			name:    "signs the complete compact JWS input",
			issuer:  NewIssuer(signer, WithIssuer("https://issuer.example")),
			options: []JwtIssuerOption{WithSubject("client"), WithClaims(Cliams{"role": "reader"})},
			assertions: func(t *testing.T, token *Token, err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
				encoder, err := NewEncoder()
				if err != nil {
					t.Fatal(err)
				}
				encoded, err := encoder.Encode(context.Background(), token)
				if err != nil {
					t.Fatal(err)
				}
				parts := strings.Split(string(encoded), ".")
				if len(parts) != 3 {
					t.Fatalf("JWT has %d parts, want 3", len(parts))
				}
				signature, err := base64.RawURLEncoding.DecodeString(parts[2])
				if err != nil {
					t.Fatal(err)
				}
				verifier := sig.SignVerifier{Kid: signer.Kid, Alg: signer.Alg, Key: &privateKey.PublicKey}
				if err := verifier.VerifySignature(signature, []byte(parts[0]+"."+parts[1])); err != nil {
					t.Fatalf("verify JWT signature: %v", err)
				}
				if token.Header["alg"] != "RS256" || token.Header["kid"] != signer.Kid {
					t.Fatalf("unexpected header: %#v", token.Header)
				}
				if token.Claims["iss"] != "https://issuer.example" || token.Claims["sub"] != "client" || token.Claims["role"] != "reader" {
					t.Fatalf("unexpected claims: %#v", token.Claims)
				}
				if _, ok := token.Claims["iat"].(int64); !ok {
					t.Fatalf("iat has type %T, want int64", token.Claims["iat"])
				}
				if jti, ok := token.Claims["jti"].(string); !ok || jti == "" {
					t.Fatalf("jti = %#v, want non-empty string", token.Claims["jti"])
				}
			},
		},
		{
			name:   "rejects nil signer",
			issuer: NewIssuer(nil),
			assertions: func(t *testing.T, token *Token, err error) {
				t.Helper()
				if token != nil {
					t.Fatalf("token = %#v, want nil", token)
				}
				if !errors.Is(err, vapi.ErrMisconfigured) {
					t.Fatalf("error = %v, want ErrMisconfigured", err)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			token, err := test.issuer.Issue(context.Background(), test.options...)
			test.assertions(t, token, err)
		})
	}
}
