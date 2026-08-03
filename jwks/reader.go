package jwks

import (
	"context"
	"io"
	"net/http"

	"github.com/veles-security/vapi"
)

type Reader struct {
	decoder vapi.Decoder[*Jwks, DecoderOption]
}

type ReaderOption interface {
	Configure(*Reader)
}

func NewReader(options ...ReaderOption) *Reader {
	reader := &Reader{}
	if len(options) == 0 {
		reader.decoder = NewDecoder()
	}
	for _, option := range options {
		option.Configure(reader)
	}
	return reader
}

// ReadArtifact implements [vapi.Reader].
func (r *Reader) ReadArtifact(ctx context.Context, carrier http.Response, options ...ReaderOption) (*Jwks, error) {
	payload, err := io.ReadAll(carrier.Body)
	if err != nil {
		return nil, err
	}
	return r.decoder.Decode(ctx, payload)
}

var _ vapi.Reader[http.Response, *Jwks, ReaderOption] = &Reader{}
