# Token endpoint presets

Package `tokenendpoint/presets` composes the standard token-request validator,
client authenticator, subject resolver, and JWT issuer while leaving the
lower-level `tokenendpoint.With...` options available for custom setups.

The usual shape is:

```go
endpoint, err := tokenendpoint.New(
	presets.Authenticator(
		presets.GrantTypes(...),
		presets.ClientAuthentication(...),
		presets.ResolveSubject(...), // optional
	),
	presets.Signer(signer),
	presets.Tokens(...),
)
```

The presence of `presets.AccessToken`, `presets.RefreshToken`, or
`presets.IDToken` enables issuance of that token type. Each callback returns
the `jwt.IssuerOption` values specific to that token. The endpoint adds
`jwt.WithPrincipal` automatically before applying those options.

## Client credentials

For a client-credentials endpoint, the authenticated client can be used as the
token subject directly. In that case no `ResolveSubject` callback is needed.
The client authentication callback must return a `vapi.ScopedPrincipal`.

```go
package authserver

import (
	"context"
	"crypto/subtle"
	"errors"
	"time"

	"github.com/veles-security/vapi"
	"github.com/veles-security/vapi/sub"
	"github.com/veles-security/vcrypt/jws"
	"github.com/veles-security/voauth/clientcredentials"
	"github.com/veles-security/voauth/jwt"
	"github.com/veles-security/voauth/tokenendpoint"
	"github.com/veles-security/voauth/tokenendpoint/presets"
	"github.com/veles-security/voauth/tokenrequest"
)

func newClientCredentialsEndpoint(
	signer vapi.Signer[jws.SignerOption, jws.JWS],
) (*tokenendpoint.TokenEndpoint, error) {
	return tokenendpoint.New(
		presets.Authenticator(
			presets.GrantTypes(tokenrequest.ClientCredentialsGrantType),
			presets.ClientAuthentication(
				clientcredentials.ClientSecretPostAuthMethod,
				authenticateClient,
			),
		),
		presets.Signer(signer),
		presets.Tokens(
			presets.AccessToken(func(
				_ context.Context,
				client vapi.ScopedPrincipal,
			) ([]jwt.IssuerOption, error) {
				return []jwt.IssuerOption{
					jwt.WithIssuer("https://auth.example.com"),
					jwt.WithExp(15 * time.Minute),
					jwt.WithClaims(jwt.Cliams{
						"token_use": "access",
					}),
				}, nil
			}),
		),
	)
}

func authenticateClient(
	_ context.Context,
	credentials *clientcredentials.ClientCredentials,
) (vapi.Principal, error) {
	// Replace this example comparison with a lookup in your client store.
	idMatches := subtle.ConstantTimeCompare(
		[]byte(credentials.ClientId),
		[]byte("service-a"),
	) == 1
	secretMatches := subtle.ConstantTimeCompare(
		[]byte(credentials.ClientSecret),
		[]byte("replace-with-stored-secret"),
	) == 1
	if !idMatches || !secretMatches {
		return nil, vapi.NewErrorCategory(
			vapi.ErrUnauthenticated,
			errors.New("invalid client credentials"),
		)
	}

	return sub.NewBasePrincipal(
		"https://auth.example.com",
		credentials.ClientId,
		"oauth2:client",
	).WithGrantedScopes("api:read"), nil
}
```

To accept HTTP Basic client authentication instead, change the method to
`clientcredentials.ClientSecretBasicAuthMethod`. Multiple methods can be
enabled by adding another `presets.ClientAuthentication` option:

```go
presets.Authenticator(
	presets.GrantTypes(tokenrequest.ClientCredentialsGrantType),
	presets.ClientAuthentication(
		clientcredentials.ClientSecretBasicAuthMethod,
		authenticateClient,
	),
	presets.ClientAuthentication(
		clientcredentials.ClientSecretPostAuthMethod,
		authenticateClient,
	),
)
```

## Authorization code

An authorization-code exchange has two distinct resolution steps:

1. `ClientAuthentication` authenticates the OAuth client.
2. `ResolveSubject` validates and consumes the authorization code, checks that
   it belongs to that client, verifies the redirect URI and PKCE verifier when
   applicable, and returns the user represented by the code.

```go
func newAuthorizationCodeEndpoint(
	signer vapi.Signer[jws.SignerOption, jws.JWS],
) (*tokenendpoint.TokenEndpoint, error) {
	return tokenendpoint.New(
		presets.Authenticator(
			presets.GrantTypes(tokenrequest.AuthorizationCodeGrantType),
			presets.ClientAuthentication(
				clientcredentials.ClientSecretBasicAuthMethod,
				authenticateClient,
			),
			presets.ResolveSubject(resolveAuthorizationCode),
		),
		presets.Signer(signer),
		presets.Tokens(
			presets.AccessToken(accessTokenOptions),
			presets.RefreshToken(refreshTokenOptions),
			presets.IDToken(idTokenOptions),
		),
	)
}

func resolveAuthorizationCode(
	ctx context.Context,
	request *tokenrequest.TokenRequest,
	client vapi.Principal,
) (vapi.Principal, error) {
	// Application code should atomically consume the code so it cannot be used
	// twice. The lookup should also verify client.Subject(), request.RedirectUri,
	// and request.CodeVerifier against the values bound to the code.
	record, err := authorizationCodes.Consume(ctx, request.Code)
	if err != nil {
		return nil, vapi.NewErrorCategory(vapi.ErrPolicyRejected, err)
	}
	if record.ClientID != client.Subject() ||
		record.RedirectURI != request.RedirectUri ||
		!record.VerifyPKCE(request.CodeVerifier) {
		return nil, vapi.NewErrorCategory(
			vapi.ErrPolicyRejected,
			errors.New("authorization code is not valid for this request"),
		)
	}

	return sub.NewBasePrincipal(
		"https://auth.example.com",
		record.SubjectID,
		"user",
	).WithGrantedScopes(record.Scopes...), nil
}

func accessTokenOptions(
	_ context.Context,
	principal vapi.ScopedPrincipal,
) ([]jwt.IssuerOption, error) {
	return []jwt.IssuerOption{
		jwt.WithIssuer("https://auth.example.com"),
		jwt.WithExp(15 * time.Minute),
		jwt.WithClaims(jwt.Cliams{"token_use": "access"}),
	}, nil
}

func refreshTokenOptions(
	_ context.Context,
	principal vapi.ScopedPrincipal,
) ([]jwt.IssuerOption, error) {
	return []jwt.IssuerOption{
		jwt.WithIssuer("https://auth.example.com"),
		jwt.WithExp(24 * time.Hour),
		jwt.WithClaims(jwt.Cliams{"token_use": "refresh"}),
	}, nil
}

func idTokenOptions(
	_ context.Context,
	principal vapi.ScopedPrincipal,
) ([]jwt.IssuerOption, error) {
	return []jwt.IssuerOption{
		jwt.WithIssuer("https://auth.example.com"),
		jwt.WithExp(15 * time.Minute),
		jwt.WithClaims(jwt.Cliams{"token_use": "id"}),
	}, nil
}
```

`authorizationCodes` and its record type in this example represent the
application's authorization-code store. Code lookup, one-time consumption,
redirect-URI checking, and PKCE verification are application policy and remain
outside the presets package.

## Combining presets with low-level options

Presets return ordinary `tokenendpoint.TokenEndpointConfigOption` values, so
they can be mixed with the existing options:

```go
endpoint, err := tokenendpoint.New(
	presets.Authenticator(
		presets.GrantTypes(tokenrequest.ClientCredentialsGrantType),
		presets.ClientAuthentication(
			clientcredentials.ClientSecretPostAuthMethod,
			authenticateClient,
		),
	),
	presets.Signer(signer),
	presets.Tokens(presets.AccessToken(accessTokenOptions)),
	tokenendpoint.WithTokenResponseWriter(customWriter),
)
```

As with all functional options, when two options replace the same endpoint
component, the later option wins.
