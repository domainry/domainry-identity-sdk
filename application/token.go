package application

import (
	"context"
	"net/http"
	"strings"

	identity "github.com/domainry/domainry-identity-sdk"
)

type tokens struct{ binding *binding }

func (value tokens) Verify(ctx context.Context, request identity.VerifyTokenRequest) (identity.VerifiedToken, error) {
	if issuer := strings.TrimSpace(request.Issuer); issuer != "" && issuer != strings.TrimSpace(value.binding.descriptor.Issuer) {
		return identity.VerifiedToken{}, scopeError(http.StatusForbidden, "identity.issuer_mismatch")
	}
	if audience := identity.ApplicationKey(strings.TrimSpace(string(request.Audience))); audience != "" && audience != value.binding.application.ApplicationKey {
		return identity.VerifiedToken{}, scopeError(http.StatusForbidden, "identity.application_mismatch")
	}
	request.Issuer = value.binding.descriptor.Issuer
	request.Audience = value.binding.application.ApplicationKey
	verified, err := value.binding.delegate.Tokens().Verify(ctx, request)
	if err != nil {
		return identity.VerifiedToken{}, err
	}
	if verified.WorkspaceID != value.binding.application.WorkspaceID || verified.Audience != value.binding.application.ApplicationKey {
		return identity.VerifiedToken{}, scopeError(http.StatusForbidden, "identity.token_scope_mismatch")
	}
	return verified, nil
}
