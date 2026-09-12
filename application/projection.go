package application

import (
	"context"

	identity "github.com/domainry/domainry-identity-sdk"
)

type projection struct{ binding *binding }

func (value projection) context(ctx context.Context) (context.Context, error) {
	scope, err := value.binding.applicationScope(ctx, identity.ApplicationScope{})
	if err != nil {
		return ctx, err
	}
	return WithScope(ctx, scope), nil
}

func (value projection) FindUser(ctx context.Context, input identity.UserLookup) (identity.User, bool, error) {
	ctx, err := value.context(ctx)
	if err != nil {
		return identity.User{}, false, err
	}
	return value.binding.delegate.Projection().FindUser(ctx, input)
}

func (value projection) FindOrganizationUnit(ctx context.Context, input identity.OrganizationUnitLookup) (identity.OrganizationUnit, bool, error) {
	ctx, err := value.context(ctx)
	if err != nil {
		return identity.OrganizationUnit{}, false, err
	}
	return value.binding.delegate.Projection().FindOrganizationUnit(ctx, input)
}

func (value projection) ResolveDisplayNames(ctx context.Context, input identity.DisplayNameQuery) (identity.DisplayNameResult, error) {
	ctx, err := value.context(ctx)
	if err != nil {
		return identity.DisplayNameResult{}, err
	}
	resolver, ok := value.binding.delegate.Projection().(identity.DisplayNameProjection)
	if !ok {
		return identity.DisplayNameResult{}, &identity.Error{Code: "identity.display_name_projection_unavailable"}
	}
	return resolver.ResolveDisplayNames(ctx, input)
}

func (value projection) ListUsers(ctx context.Context, input identity.ProjectionQuery) ([]identity.User, error) {
	ctx, err := value.context(ctx)
	if err != nil {
		return nil, err
	}
	return value.binding.delegate.Projection().ListUsers(ctx, input)
}

func (value projection) ListRoles(ctx context.Context, input identity.ProjectionQuery) ([]identity.Role, error) {
	ctx, err := value.context(ctx)
	if err != nil {
		return nil, err
	}
	return value.binding.delegate.Projection().ListRoles(ctx, input)
}

func (value projection) ListUserRoleAssignments(ctx context.Context, input identity.UserRoleAssignmentQuery) ([]identity.UserRoleAssignment, error) {
	ctx, err := value.context(ctx)
	if err != nil {
		return nil, err
	}
	return value.binding.delegate.Projection().ListUserRoleAssignments(ctx, input)
}

var _ identity.DisplayNameProjection = projection{}
