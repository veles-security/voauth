package jwk

import "net/url"

type JwkRepresentation struct {
	Use       string      `json:"use,omitempty"`
	Kty       string      `json:"kty,omitempty"`
	Kid       string      `json:"kid,omitempty"`
	Crv       string      `json:"crv,omitempty"`
	Alg       string      `json:"alg,omitempty"`
	K         *byteBuffer `json:"k,omitempty"`
	X         *byteBuffer `json:"x,omitempty"`
	Y         *byteBuffer `json:"y,omitempty"`
	N         *byteBuffer `json:"n,omitempty"`
	E         *byteBuffer `json:"e,omitempty"`
	X5c       []string    `json:"x5c,omitempty"`
	X5u       *url.URL    `json:"x5u,omitempty"`
	X5tSHA1   string      `json:"x5t,omitempty"`
	X5tSHA256 string      `json:"x5t#S256,omitempty"`
}

type byteBuffer string
