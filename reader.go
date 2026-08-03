package voauth

import (
	"context"
	"errors"
	"net/http"
	"strings"

	velesapi "github.com/veles-security/vapi"
)

type JwtReader struct {
	decoder velesapi.Decoder[*JwtToken, JwtDecoderOption]
}

type JwtReaderOption func(*JwtReader)

func NewJwtExtractor(options ...JwtReaderOption) *JwtReader {
	extractor := &JwtReader{}
	for _, option := range options {
		option(extractor)
	}
	if extractor.decoder == nil {
		extractor.decoder = NewJwtDecoder()
	}
	return extractor
}

// AddCredentials implements [velesapi.Reader].
func (j *JwtReader) ReadArtifact(ctx context.Context, request *http.Request, options ...JwtReaderOption) (*JwtToken, error) {
	if request == nil {
		return nil, velesapi.NewErrorCategory(velesapi.ErrMalformed, errors.New("nil request"))
	}

	values := request.Header.Values("Authorization")
	if len(values) == 0 {
		return nil, velesapi.ErrNotApplicable
	}
	if len(values) != 1 {
		return nil, velesapi.NewErrorCategory(velesapi.ErrUnauthenticated, errors.New("ambiguous authorization credentials"))
	}

	scheme, credential, found := strings.Cut(values[0], " ")
	if !strings.EqualFold(scheme, "Bearer") {
		return nil, velesapi.ErrNotApplicable
	}
	if !found || credential == "" || strings.ContainsAny(credential, " \t\r\n,") {
		return nil, velesapi.NewErrorCategory(velesapi.ErrUnauthenticated, errors.New("malformed bearer credentials"))
	}

	return j.decoder.Decode(ctx, []byte(credential))
}

var _ velesapi.Reader[*http.Request, *JwtToken, JwtReaderOption] = &JwtReader{}
