package velesoauth

import (
	"context"
	"errors"
	"net/http"
	"strings"

	velesapi "github.com/veles-security/vapi"
)

type JwtExtractor struct {
	Decoder velesapi.DecodeSchemer[*JwtToken, JwtDecoderOption]
}

type JwtExtractorOption struct {
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

	return j.Decoder.Decode(ctx, []byte(credential))
}

var _ velesapi.ExtractorSchemer[*http.Request, *JwtToken, JwtExtractorOption] = &JwtExtractor{}
