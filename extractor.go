package voauth

import (
	"context"
	"errors"
	"net/http"
	"strings"

	velesapi "github.com/veles-security/vapi"
)

type JwtExtractor struct {
	decoder velesapi.Decoder[*JwtToken, JwtDecoderOption]
}

type JwtExtractorOption func(*JwtExtractor)

func NewJwtExtractor(options ...JwtExtractorOption) *JwtExtractor {
	extractor := &JwtExtractor{}
	for _, option := range options {
		option(extractor)
	}
	if extractor.decoder == nil {
		extractor.decoder = NewJwtDecoder()
	}
	return extractor
}

// AddCredentials implements [velesapi.ExtractorSchemer].
func (j *JwtExtractor) ExtractArtifact(ctx context.Context, request *http.Request, options ...JwtExtractorOption) (*JwtToken, error) {
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

var _ velesapi.Extractor[*http.Request, *JwtToken, JwtExtractorOption] = &JwtExtractor{}
