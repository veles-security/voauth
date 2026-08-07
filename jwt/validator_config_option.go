package jwt

// WithValidatorRuntimeOptions configures validator options that are applied to
// every Validate call before its per-call options.
func WithValidatorRuntimeOptions(options ...ValidatorOption) ValidatorConfigOption {
	return func(validator *Validator) error {
		validator.runtimeOptions = append([]ValidatorOption(nil), options...)
		return nil
	}
}
