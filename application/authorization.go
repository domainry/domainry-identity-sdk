package application

import (
	"context"
	"net/http"

	identity "github.com/domainry/domainry-identity-sdk"
)

type authorization struct{ binding *binding }

func (value authorization) ResolveAccess(ctx context.Context, request identity.AccessBundleRequest) (identity.AccessBundle, error) {
	if _, err := value.binding.verifyAccessToken(ctx, request.Identity.AccessToken); err != nil {
		return identity.AccessBundle{}, err
	}
	return value.binding.delegate.Authorization().ResolveAccess(ctx, request)
}

func (value authorization) Reauthorize(ctx context.Context, request identity.DecisionRequest) (identity.AccessDecision, error) {
	if _, err := value.binding.verifyAccessToken(ctx, request.Identity.AccessToken); err != nil {
		return identity.AccessDecision{}, err
	}
	return value.binding.delegate.Authorization().Reauthorize(ctx, request)
}

type principals struct{ binding *binding }

func (value principals) Resolve(ctx context.Context, request identity.PrincipalResolutionRequest) (identity.PrincipalResolution, error) {
	scope, err := value.binding.applicationScope(ctx, identity.ApplicationScope{})
	if err != nil {
		return identity.PrincipalResolution{}, err
	}
	resolution, err := value.binding.delegate.Principals().Resolve(WithScope(ctx, scope), request)
	if err != nil {
		return identity.PrincipalResolution{}, err
	}
	if resolution.Principal.WorkspaceID != string(scope.WorkspaceID) ||
		resolution.Principal.UserID != string(request.SubjectID) ||
		resolution.AccessBundle.Subject.WorkspaceID != scope.WorkspaceID ||
		resolution.AccessBundle.Subject.SubjectID != request.SubjectID {
		return identity.PrincipalResolution{}, scopeError(http.StatusBadGateway, "identity.principal_scope_invalid")
	}
	resolution.Principal.AccessBundle = &resolution.AccessBundle
	return resolution, nil
}
