package jwks_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"reflect"
	"testing"

	"github.com/veles-security/vapi/sig"
	"github.com/veles-security/voauth/jwk"
	"github.com/veles-security/voauth/jwks"
)

func TestEncoder_Encode(t *testing.T) {
	keyRSA2048, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	newECDSA := func(curve elliptic.Curve) *ecdsa.PrivateKey {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	keyES256 := newECDSA(elliptic.P256())
	keyES384 := newECDSA(elliptic.P384())
	keyES512 := newECDSA(elliptic.P521())
	keyEd25519Public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		artifact *jwks.Jwks
	}{
		{
			name: "RSA key with RS256",
			artifact: &jwks.Jwks{Keys: []jwk.Jwk{*jwk.NewJwk(
				sig.SigAlgRS256,
				keyRSA2048.Public(),
				"rsa-key",
			)}},
		},
		{
			name: "RSA key with RS384",
			artifact: &jwks.Jwks{Keys: []jwk.Jwk{*jwk.NewJwk(
				sig.SigAlgRS384,
				keyRSA2048.Public(),
				"rsa-key",
			)}},
		},
		{
			name: "ECDSA key with keyES256",
			artifact: &jwks.Jwks{Keys: []jwk.Jwk{*jwk.NewJwk(
				sig.SigAlgES256,
				keyES256.Public(),
				"ecdsa-key",
			)}},
		},
		{
			name: "ECDSA key with ES384",
			artifact: &jwks.Jwks{Keys: []jwk.Jwk{*jwk.NewJwk(
				sig.SigAlgES384,
				keyES384.Public(),
				"ecdsa-key",
			)}},
		},
		{
			name: "ECDSA key with ES512",
			artifact: &jwks.Jwks{Keys: []jwk.Jwk{*jwk.NewJwk(
				sig.SigAlgES512,
				keyES512.Public(),
				"ecdsa-key",
			)}},
		},
		{
			name: "Ed25519 key with EdDSA",
			artifact: &jwks.Jwks{Keys: []jwk.Jwk{*jwk.NewJwk(
				sig.SigAlgEd25519,
				keyEd25519Public,
				"ed25519-key",
			)}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded, err := jwks.NewEncoder()
			if err != nil {
				t.Fatalf("NewEncoder() failed: %v", err)
			}
			payload, err := encoded.Encode(context.Background(), tt.artifact)
			if err != nil {
				t.Fatalf("Encode() failed: %v", err)
			}

			decoder, err := jwks.NewDecoder()
			if err != nil {
				t.Fatalf("NewDecoder() failed: %v", err)
			}
			decoded, err := decoder.Decode(context.Background(), payload)
			if err != nil {
				t.Fatalf("Decode() failed: %v", err)
			}
			if !reflect.DeepEqual(decoded, tt.artifact) {
				t.Errorf("decoded JWKS = %#v, want %#v", decoded, tt.artifact)
			}
		})
	}
}
