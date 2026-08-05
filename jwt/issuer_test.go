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

func TestNewIssuer(t *testing.T) {
	tests := []struct {
		name    string
		options []IssuerConfigOption
		wantErr error
	}{
		{name: "defaults to unsigned tokens"},
		{name: "rejects nil option", options: []IssuerConfigOption{nil}, wantErr: vapi.ErrMisconfigured},
		{name: "categorizes option error", options: []IssuerConfigOption{func(*Issuer) error { return errors.New("failure") }}, wantErr: vapi.ErrMisconfigured},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			issuer, err := NewIssuer(test.options...)
			if test.wantErr != nil {
				if issuer != nil || !errors.Is(err, test.wantErr) {
					t.Fatalf("NewIssuer() = (%#v, %v), want nil and %v", issuer, err, test.wantErr)
				}
				return
			}
			if err != nil || issuer == nil {
				t.Fatalf("NewIssuer() = (%#v, %v), want non-nil issuer", issuer, err)
			}
		})
	}
}

func TestIssuer_Issue(t *testing.T) {
	privateKey := testkeys.Private(t, testkeys.RSA2048).(*rsa.PrivateKey)
	signer := &sig.Signer{Kid: "test-key", Alg: sig.SigAlgRS256, Key: privateKey}
	signedIssuer, err := NewIssuer(WithSigner(signer))
	if err != nil {
		t.Fatal(err)
	}
	unsignedIssuer, err := NewIssuer()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		issuer     *Issuer
		options    []IssuerOption
		assertions func(*testing.T, *Token, error)
	}{
		{
			name: "signs after runtime decorators execute", issuer: signedIssuer,
			options: []IssuerOption{WithIssuer("https://issuer.example"), WithSubject("client"), WithClaims(Cliams{"role": "reader"})},
			assertions: func(t *testing.T, token *Token, err error) {
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
			name: "issues unsigned token without signer", issuer: unsignedIssuer,
			assertions: func(t *testing.T, token *Token, err error) {
				if err != nil {
					t.Fatal(err)
				}
				if token.Header["alg"] != "none" || len(token.signature) != 0 {
					t.Fatalf("unsigned token = header %#v, signature %x", token.Header, token.signature)
				}
				encoder, err := NewEncoder()
				if err != nil {
					t.Fatal(err)
				}
				encoded, err := encoder.Encode(context.Background(), token)
				if err != nil {
					t.Fatal(err)
				}
				if !strings.HasSuffix(string(encoded), ".") {
					t.Fatalf("unsigned compact JWT %q does not have an empty signature", encoded)
				}
			},
		},
		{name: "rejects nil receiver", issuer: nil, assertions: func(t *testing.T, token *Token, err error) {
			if token != nil || !errors.Is(err, vapi.ErrMisconfigured) {
				t.Fatalf("Issue() = (%#v, %v), want nil and ErrMisconfigured", token, err)
			}
		}},
		{name: "rejects nil runtime option", issuer: unsignedIssuer, options: []IssuerOption{nil}, assertions: func(t *testing.T, token *Token, err error) {
			if token != nil || !errors.Is(err, vapi.ErrMisconfigured) {
				t.Fatalf("Issue() = (%#v, %v), want nil and ErrMisconfigured", token, err)
			}
		}},
		{name: "rejects nil decorator result", issuer: unsignedIssuer, options: []IssuerOption{func(IssueFunc) IssueFunc { return nil }}, assertions: func(t *testing.T, token *Token, err error) {
			if token != nil || !errors.Is(err, vapi.ErrMisconfigured) {
				t.Fatalf("Issue() = (%#v, %v), want nil and ErrMisconfigured", token, err)
			}
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			token, err := test.issuer.Issue(context.Background(), test.options...)
			test.assertions(t, token, err)
		})
	}
}
