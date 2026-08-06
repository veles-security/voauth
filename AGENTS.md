# voauth development guide

These instructions apply to all code under `voauth/`.

## Implementation style

Use `jwks.Decoder` as the canonical implementation pattern for every implementation of a `vapi` interface that accepts options, including `vapi.Reader`, `vapi.Writer`, `vapi.Encoder`, and `vapi.Decoder`. Existing code that does not follow this pattern is not a precedent for new work.

An option-bearing implementation must:

- define separate configuration and runtime option types;
- define configuration options as `func(*Type) error` and apply them in a constructor that returns `(*Type, error)`;
- reject nil configuration options and categorize configuration failures with `vapi.NewErrorCategory(vapi.ErrMisconfigured, ...)`;
- define a named runtime function type such as `DecodeFunc`, `EncodeFunc`, `ReadFunc`, or `WriteFunc`;
- define runtime options as decorators of that function type, for example `type DecoderOption func(next DecodeFunc) DecodeFunc`;
- store constructor-configured runtime options in a `runtimeOptions` field and apply them before the runtime options passed to the interface method, so per-call options can wrap or override the configured behavior;
- provide a configuration option that sets those constructor-configured runtime options, such as `WithEncoderRuntimeOptions`;
- build the runtime decorator chain in reverse order so options execute in caller-supplied order;
- reject nil runtime options and decorators that return a nil function, including the option index in the error;
- keep the undecorated operation in a private method such as `decode`, `encode`, `readArtifact`, or `writeArtifact`;
- provide safe defaults for required collaborators in the constructor;
- for each configurable dependency, provide configuration options both to inject the dependency directly and to construct it from that dependency's configuration options, as exemplified by `WithEncoderJwkEncoder` and `WithEncoderJwkEncoderOptions`;
- prefix configuration-option names with the configured implementation type, for example `WithEncoder...` for `EncoderConfigOption`, including dependency and runtime-option configuration;
- include a compile-time interface assertion;
- perform thorough nil and invalid-state checks before dereferencing receivers, collaborators, carriers, payloads, or artifacts; and
- wrap errors with useful operation context using `%w`, then categorize them with `vapi.NewErrorCategory` and the appropriate stable `vapi` error category.

Preserve the underlying error when adding context or a category so callers can inspect both the stable category and the cause with `errors.Is`/`errors.As`. Do not return uncategorized errors from public constructors or `vapi` interface methods.

Match the file organization and naming used by `jwks.Decoder` when practical. Put non-trivial configuration-option implementations in a dedicated `*_config_option.go` file.

## Tests

Use `TestEncoder_Encode` in `jwks/encoder_test.go` as the canonical test pattern.

Tests must:

- be organized per public function or method, with names such as `TestEncoder_Encode` and `TestNewEncoder`;
- use table-driven cases and `t.Run`;
- define assertion callbacks such as `assertDecoded` and `assertMalformed`, and select the appropriate assertion in each test case;
- use `errors.Is` to verify `vapi` error categories;
- compare complete results where practical, using `reflect.DeepEqual` when appropriate;
- cover success, malformed input, misconfiguration, nil values, and option/decorator failures relevant to the function; and
- use `voauth/internal/testkeys` for cryptographic test material whenever applicable. Do not create ad hoc keys when `testkeys` can supply the case.

Keep tests scoped to the function under test. The test-local assertion callbacks required by this section are permitted and do not require separate approval.

## Approval required for additional functions

Do not introduce any additional production function or method—including convenience functions, helper functions, constructors, adapters, or wrappers—without explicit human approval. If implementation appears to require one, stop and request approval before adding it.

Functions and methods explicitly required by the requested interface or feature are in scope. Test functions and the test-local assertion callbacks mandated above are also in scope. Any other new function requires approval.
