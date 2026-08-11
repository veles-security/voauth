package tokenrequest

func WithResolveFunc(f ResolveFunc) ResolverOption {
	return func(next ResolveFunc) ResolveFunc {
		return f
	}
}
