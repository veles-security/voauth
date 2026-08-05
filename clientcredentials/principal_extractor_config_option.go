package clientcredentials

import "errors"

// WithAuthCallback configures the callback that validates credentials and returns their principal.
func WithAuthCallback(callback AuthCallback) PrincipalExtractorConfigOption {
	return func(extractor *PrincipalExtractor) error {
		if callback == nil {
			return errors.New("nil client credentials auth callback")
		}
		extractor.authCallback = callback
		return nil
	}
}
