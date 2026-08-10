package clientcredentials

func WithArtifactAuthenticatorRuntimeOptions(options ...ArtifactAuthenticatorOption) ArtifactAuthenticatorConfigOption {
	return func(authenticator *ArtifactAuthenticator) error {
		authenticator.runtimeOptions = append([]ArtifactAuthenticatorOption(nil), options...)
		return nil
	}
}
