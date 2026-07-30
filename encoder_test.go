package velesoauth_test

import (
	"context"
	"testing"

	velesoauth "github.com/veles-security/voauth"
)

func TestJwtEncoder_Encode(t *testing.T) {
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
			// TODO: update the condition below to compare got with tt.want.
			if string(tt.want) != string(got) {
				t.Errorf("Encode() = %v, want %v", string(got), string(tt.want))
			}
		})
	}
}
