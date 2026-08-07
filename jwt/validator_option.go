package jwt

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/veles-security/vapi"
)

// WithType requires the JWT typ header to equal tokenType.
func WithType(tokenType string) ValidatorOption {
	return func(next ValidateFunc) ValidateFunc {
		return func(ctx context.Context, token *Token) error {
			if token.Header["typ"] != tokenType {
				return vapi.NewErrorCategory(vapi.ErrPolicyRejected, errors.New("JWT has the wrong type"))
			}
			return next(ctx, token)
		}
	}
}

// WithNonce requires the JWT nonce claim to equal nonce.
func WithNonce(nonce string) ValidatorOption {
	return func(next ValidateFunc) ValidateFunc {
		return func(ctx context.Context, token *Token) error {
			claim, ok := token.Claims["nonce"]
			if !ok {
				return vapi.NewErrorCategory(vapi.ErrBinding, errors.New("JWT nonce is missing"))
			}
			value, ok := claim.(string)
			if !ok {
				return vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("JWT claim 'nonce' must be a string"))
			}
			if subtle.ConstantTimeCompare([]byte(value), []byte(nonce)) != 1 {
				return vapi.NewErrorCategory(vapi.ErrBinding, errors.New("JWT has the wrong nonce"))
			}
			return next(ctx, token)
		}
	}
}

// WithValidIssuer requires the JWT issuer claim to equal issuer.
func WithValidIssuer(issuer string) ValidatorOption {
	return func(next ValidateFunc) ValidateFunc {
		return func(ctx context.Context, token *Token) error {
			claim, ok := token.Claims["iss"]
			if !ok {
				return vapi.NewErrorCategory(vapi.ErrWrongIssuer, errors.New("JWT issuer is missing"))
			}
			value, ok := claim.(string)
			if !ok {
				return vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("JWT claim 'iss' must be a string"))
			}
			if value != issuer {
				return vapi.NewErrorCategory(vapi.ErrWrongIssuer, errors.New("JWT has the wrong issuer"))
			}
			return next(ctx, token)
		}
	}
}

// WithValidAudience requires at least one JWT audience to match audiences.
func WithValidAudience(audiences ...string) ValidatorOption {
	return func(next ValidateFunc) ValidateFunc {
		return func(ctx context.Context, token *Token) error {
			claim, ok := token.Claims["aud"]
			if !ok {
				return vapi.NewErrorCategory(vapi.ErrWrongAudience, errors.New("JWT audience is missing"))
			}

			matches := func(value string) bool {
				for _, expected := range audiences {
					if value == expected {
						return true
					}
				}
				return false
			}

			switch value := claim.(type) {
			case string:
				if value == "" {
					return vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("JWT claim 'aud' must not be empty"))
				}
				if matches(value) {
					return next(ctx, token)
				}
			case []any:
				if len(value) == 0 {
					return vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("JWT claim 'aud' must not be empty"))
				}
				matched := false
				for _, item := range value {
					text, ok := item.(string)
					if !ok || text == "" {
						return vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("JWT claim 'aud' must contain only strings"))
					}
					if matches(text) {
						matched = true
					}
				}
				if matched {
					return next(ctx, token)
				}
			case []string:
				if len(value) == 0 {
					return vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("JWT claim 'aud' must not be empty"))
				}
				matched := false
				for _, item := range value {
					if item == "" {
						return vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("JWT claim 'aud' must contain only strings"))
					}
					if matches(item) {
						matched = true
					}
				}
				if matched {
					return next(ctx, token)
				}
			default:
				return vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("JWT claim 'aud' must be a string or an array of strings"))
			}
			return vapi.NewErrorCategory(vapi.ErrWrongAudience, errors.New("JWT has the wrong audience"))
		}
	}
}

// WithValidClock rejects expired JWTs and JWTs that are not valid yet, using
// leeway as clock skew tolerance.
func WithValidClock(leeway time.Duration) ValidatorOption {
	return func(next ValidateFunc) ValidateFunc {
		return func(ctx context.Context, token *Token) error {
			now := float64(time.Now().UnixNano()) / float64(time.Second)
			if exp, ok, err := numericDate(token.Claims, "exp"); err != nil {
				return err
			} else if ok && now >= exp+leeway.Seconds() {
				return vapi.NewErrorCategory(vapi.ErrExpired, errors.New("JWT expired"))
			}
			if nbf, ok, err := numericDate(token.Claims, "nbf"); err != nil {
				return err
			} else if ok && now+leeway.Seconds() < nbf {
				return vapi.NewErrorCategory(vapi.ErrNotYetValid, errors.New("JWT is not valid yet"))
			}
			return next(ctx, token)
		}
	}
}

func numericDate(claims map[string]any, name string) (float64, bool, error) {
	value, ok := claims[name]
	if !ok {
		return 0, false, nil
	}

	switch value := value.(type) {
	case float64:
		return value, true, nil
	case json.Number:
		number, err := value.Float64()
		if err == nil {
			return number, true, nil
		}
	}
	return 0, false, vapi.NewErrorCategory(
		vapi.ErrMalformed,
		fmt.Errorf("JWT claim %q must be a numeric date", name),
	)
}
