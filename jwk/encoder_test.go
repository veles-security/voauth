package jwk_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"reflect"
	"testing"

	"github.com/veles-security/vapi/sig"
	"github.com/veles-security/voauth/jwk"
)

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
			artifact: &jwk.Jwk{Kid: "x", Alg: sig.SigAlgRS256, Key: keyRSA2048.Public()},
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
