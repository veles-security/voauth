package clientcredentials

func WithResolverRuntimeOptions(options ...ResolverOption) ResolverConfigOption {
	return func(authenticator *Resolver) error {
		authenticator.runtimeOptions = append([]ResolverOption(nil), options...)
		return nil
	}
}
