package jwk_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"reflect"
	"testing"

	"github.com/veles-security/vapi/sig"
	"github.com/veles-security/voauth/jwk"
)

type encoderOptionFunc func(jwk.EncodeFunc) jwk.EncodeFunc

func (f encoderOptionFunc) Apply(next jwk.EncodeFunc) jwk.EncodeFunc {
	return f(next)
}

func TestEncoderOption_DecoratesEncode(t *testing.T) {
	var calls []string
	option := encoderOptionFunc(func(next jwk.EncodeFunc) jwk.EncodeFunc {
		return func(ctx context.Context, artifact *jwk.Jwk, representation *jwk.JwkRepresentation) error {
			calls = append(calls, "before")
			err := next(ctx, artifact, representation)
			calls = append(calls, "after")
			return err
		}
	})

	encoder := jwk.NewEncoder(option)

	_, err := encoder.Encode(context.Background(), jwk.NewJwk(sig.SigAlgEd25519, make(ed25519.PublicKey, ed25519.PublicKeySize), ""))
	if err != nil {
		t.Fatalf("Encode() failed: %v", err)
	}
	if want := []string{"before", "after"}; !reflect.DeepEqual(calls, want) {
		t.Errorf("decorator calls = %v, want %v", calls, want)
	}
}

func TestEncoder_ThumbprintKid(t *testing.T) {
	publicKey := ed25519.PublicKey{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
	}

	tests := []struct {
		name     string
		encoder  *jwk.Encoder
		artifact *jwk.Jwk
		options  []jwk.EncoderOption
		wantKid  string
	}{
		{
			name:     "constructor option calculates RFC 7638 thumbprint",
			encoder:  jwk.NewEncoder(jwk.WithThumbprintKid()),
			artifact: jwk.NewJwk(sig.SigAlgEd25519, publicKey, ""),
			wantKid:  "P7IdLIpiTZiFaIoOSqbX3JrSyps3hvZ4Y2SieP96XIY",
		},
		{
			name:     "encode option calculates thumbprint",
			encoder:  jwk.NewEncoder(),
			artifact: jwk.NewJwk(sig.SigAlgEd25519, publicKey, ""),
			options:  []jwk.EncoderOption{jwk.WithThumbprintKid()},
			wantKid:  "P7IdLIpiTZiFaIoOSqbX3JrSyps3hvZ4Y2SieP96XIY",
		},
		{
			name:     "explicit kid is preserved",
			encoder:  jwk.NewEncoder(jwk.WithThumbprintKid()),
			artifact: jwk.NewJwk(sig.SigAlgEd25519, publicKey, "explicit"),
			wantKid:  "explicit",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded, err := tt.encoder.Encode(context.Background(), tt.artifact, tt.options...)
			if err != nil {
				t.Fatalf("Encode() failed: %v", err)
			}
			decoded, err := jwk.NewDecoder().Decode(context.Background(), encoded)
			if err != nil {
				t.Fatalf("Decode() failed: %v", err)
			}
			if decoded.Kid != tt.wantKid {
				t.Errorf("decoded Kid = %q, want %q", decoded.Kid, tt.wantKid)
			}
		})
	}
}

func TestEncoder_Encode(t *testing.T) {
	keyRSA2048, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		artifact *jwk.Jwk
		want     []byte
		wantErr  bool
	}{
		{
			name:     "simple",
			artifact: jwk.NewJwk(sig.SigAlgRS256, keyRSA2048.Public(), "x"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j := jwk.NewEncoder()
			got, gotErr := j.Encode(context.Background(), tt.artifact)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("Encode() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("Encode() succeeded unexpectedly")
			}
			decoded, err := jwk.NewDecoder().Decode(context.Background(), got)
			if err != nil {
				t.Fatalf("Decode() failed: %v", err)
			}
			if decoded.Kid != tt.artifact.Kid {
				t.Errorf("decoded Kid = %q, want %q", decoded.Kid, tt.artifact.Kid)
			}
			if decoded.Alg != tt.artifact.Alg {
				t.Errorf("decoded Alg = %v, want %v", decoded.Alg, tt.artifact.Alg)
			}
			if !reflect.DeepEqual(decoded.Key, tt.artifact.Key) {
				t.Errorf("decoded Key = %v, want %v", decoded.Key, tt.artifact.Key)
			}
		})
	}
}
