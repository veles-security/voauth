package jwt

// WithResolverRuntimeOptions configures resolver
// options that are applied to every Resolve call before its
// per-call options.
func WithResolverRuntimeOptions(options ...ResolverOption) ResolverConfigOption {
	return func(authenticator *Resolver) error {
		authenticator.runtimeOptions = append([]ResolverOption(nil), options...)
		return nil
	}
}
