package principal

import identity "github.com/domainry/domainry-identity-sdk/authorization"

// NewAuthenticator selects an explicitly composed external authentication
// boundary, otherwise preserving the standard token/session/bundle resolver.
// Both paths publish the same SDK Principal and use the same business evaluator.
func NewAuthenticator(binding Binding, options Options) (identity.PrincipalAuthenticator, error) {
	if source, ok := binding.(interface {
		PrincipalAuthenticator() identity.PrincipalAuthenticator
	}); ok {
		authenticator := source.PrincipalAuthenticator()
		if authenticator == nil {
			return nil, &identity.Error{Code: "identity.authenticator_required"}
		}
		return authenticator, nil
	}
	return NewResolver(binding, options)
}
