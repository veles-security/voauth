package jwt

// WithArtifactAuthenticatorRuntimeOptions configures artifact authenticator
// options that are applied to every AuthenticateArtifact call before its
// per-call options.
func WithArtifactAuthenticatorRuntimeOptions(options ...ArtifactAuthenticatorOption) ArtifactAuthenticatorConfigOption {
	return func(authenticator *ArtifactAuthenticator) error {
		authenticator.runtimeOptions = append([]ArtifactAuthenticatorOption(nil), options...)
		return nil
	}
}
