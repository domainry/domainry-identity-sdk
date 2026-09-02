package application

import (
	"context"

	identity "github.com/domainry/domainry-identity-sdk"
)

type directory struct{ binding *binding }

func (value directory) query(input identity.DirectoryQuery) (identity.DirectoryQuery, error) {
	scope, err := value.binding.applicationScope(input.Application)
	input.Application = scope
	return input, err
}

func (value directory) FindUser(ctx context.Context, input identity.UserLookup) (identity.User, bool, error) {
	scope, err := value.binding.applicationScope(input.Application)
	if err != nil {
		return identity.User{}, false, err
	}
	input.Application = scope
	return value.binding.delegate.Directory().FindUser(ctx, input)
}

func (value directory) FindOrganizationUnit(ctx context.Context, input identity.OrganizationUnitLookup) (identity.OrganizationUnit, bool, error) {
	scope, err := value.binding.applicationScope(input.Application)
	if err != nil {
		return identity.OrganizationUnit{}, false, err
	}
	input.Application = scope
	return value.binding.delegate.Directory().FindOrganizationUnit(ctx, input)
}

func (value directory) ListUsers(ctx context.Context, input identity.DirectoryQuery) ([]identity.User, error) {
	input, err := value.query(input)
	if err != nil {
		return nil, err
	}
	return value.binding.delegate.Directory().ListUsers(ctx, input)
}

func (value directory) ListRoles(ctx context.Context, input identity.DirectoryQuery) ([]identity.Role, error) {
	input, err := value.query(input)
	if err != nil {
		return nil, err
	}
	return value.binding.delegate.Directory().ListRoles(ctx, input)
}

func (value directory) ListUserRoleAssignments(ctx context.Context, input identity.UserRoleAssignmentQuery) ([]identity.UserRoleAssignment, error) {
	scope, err := value.binding.applicationScope(input.Application)
	if err != nil {
		return nil, err
	}
	input.Application = scope
	return value.binding.delegate.Directory().ListUserRoleAssignments(ctx, input)
}
