package tokenresponse

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/veles-security/vapi"
)

func TestNewReaderLimits(t *testing.T) {
	reader, err := NewReader(WithReaderMaxBodyBytes(1))
	if err != nil || reader == nil {
		t.Fatalf("NewReader() = (%#v, %v), want configured reader", reader, err)
	}
	reader, err = NewReader(WithReaderMaxBodyBytes(0))
	if reader != nil || !errors.Is(err, vapi.ErrMisconfigured) {
		t.Fatalf("NewReader() = (%#v, %v), want (nil, %v)", reader, err, vapi.ErrMisconfigured)
	}
}

func TestReader_ReadArtifactBodyLimit(t *testing.T) {
	reader, err := NewReader(WithReaderMaxBodyBytes(4))
	if err != nil {
		t.Fatalf("NewReader() failed: %v", err)
	}
	response := &http.Response{Body: io.NopCloser(strings.NewReader("oversized"))}
	artifact, err := reader.ReadArtifact(context.Background(), response)
	if artifact != nil || !errors.Is(err, vapi.ErrMalformed) {
		t.Fatalf("ReadArtifact() = (%#v, %v), want (nil, %v)", artifact, err, vapi.ErrMalformed)
	}
}
