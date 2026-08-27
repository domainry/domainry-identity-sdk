// Package identity is the cohesive SDK facade. Domain contracts are owned by
// the authentication, authorization, and identity subpackages; this root
// package composes them into one deployment-neutral Binding.
package identity

import (
	"context"
	"time"

	"github.com/domainry/domainry-identity-sdk/authentication"
	"github.com/domainry/domainry-identity-sdk/authorization"
	identitymodel "github.com/domainry/domainry-identity-sdk/identity"
)

type DeploymentMode string

const (
	DeploymentModeModule DeploymentMode = "module"
	DeploymentModeSaaS   DeploymentMode = "saas"
)

type Descriptor struct {
	ProtocolVersion string         `json:"protocol_version"`
	BundleVersion   string         `json:"bundle_version"`
	CatalogVersion  string         `json:"catalog_version"`
	Mode            DeploymentMode `json:"mode"`
	Issuer          string         `json:"issuer,omitempty"`
	Audience        string         `json:"audience,omitempty"`
	Capabilities    []string       `json:"capabilities"`
}

// Binding is the sole deployment-neutral Runtime dependency. An in-process
// module and the remote SaaS adapter expose the same cohesive capabilities.
type Binding interface {
	Descriptor() Descriptor
	Authentication() Authentication
	Tokens() TokenVerifier
	Authorization() Authorization
	Principals() PrincipalResolver
	Directory() Directory
	Catalog() CatalogClient
	Credentials() CredentialManager
	Close(context.Context) error
}

type Factory interface {
	Open(context.Context, ApplicationRef) (Binding, error)
}

type Clock interface {
	Now() time.Time
}

const (
	ProtocolVersionV1               = "domainry-identity-protocol-v1"
	CurrentProtocolVersion          = ProtocolVersionV1
	PolicyBundleVersionV1           = authorization.PolicyBundleVersionV1
	PolicyBundleVersionV2           = authorization.PolicyBundleVersionV2
	CurrentPolicyBundleVersion      = authorization.CurrentPolicyBundleVersion
	CatalogVersionV1                = authorization.CatalogVersionV1
	PrincipalContextContractVersion = authorization.PrincipalContextContractVersion
	EffectAllow                     = authorization.EffectAllow
	EffectDeny                      = authorization.EffectDeny
	ExportModeDeny                  = authorization.ExportModeDeny
	ExportModeAllowList             = authorization.ExportModeAllowList
	OperatorEqual                   = authorization.OperatorEqual
	OperatorNotEqual                = authorization.OperatorNotEqual
	OperatorIn                      = authorization.OperatorIn
	OperatorNotIn                   = authorization.OperatorNotIn
	OperatorExists                  = authorization.OperatorExists
	OperatorPrefix                  = authorization.OperatorPrefix
	OperatorContains                = authorization.OperatorContains
	FieldEffectAllow                = authorization.FieldEffectAllow
	FieldEffectDeny                 = authorization.FieldEffectDeny
	FieldEffectHide                 = authorization.FieldEffectHide
	FieldEffectMask                 = authorization.FieldEffectMask
	MaskTypePhone                   = authorization.MaskTypePhone
	MaskTypeIDNumber                = authorization.MaskTypeIDNumber
	MaskTypeEmail                   = authorization.MaskTypeEmail
	MaskTypeYearOnly                = authorization.MaskTypeYearOnly
	MaskTypeLastN                   = authorization.MaskTypeLastN
	RelationForward                 = authorization.RelationForward
	RelationReverse                 = authorization.RelationReverse
)

type Error = identitymodel.Error
type TenantID = identitymodel.TenantID
type WorkspaceID = identitymodel.WorkspaceID
type SubjectID = identitymodel.SubjectID
type SessionID = identitymodel.SessionID
type ApplicationKey = identitymodel.ApplicationKey
type ResourceType = identitymodel.ResourceType
type Action = identitymodel.Action
type AuthorizationRevision = identitymodel.AuthorizationRevision
type CatalogRevision = identitymodel.CatalogRevision
type User = identitymodel.User
type Department = identitymodel.Department
type Role = identitymodel.Role
type UserRoleAssignment = identitymodel.UserRoleAssignment
type WorkforceEntry = identitymodel.WorkforceEntry
type ApplicationScope = identitymodel.ApplicationScope
type DirectoryQuery = identitymodel.DirectoryQuery
type UserLookup = identitymodel.UserLookup
type DepartmentLookup = identitymodel.DepartmentLookup
type UserRoleAssignmentQuery = identitymodel.UserRoleAssignmentQuery
type Directory = identitymodel.Directory

type AuthSession = authentication.AuthSession
type Provider = authentication.Provider
type ProviderChallenge = authentication.ProviderChallenge
type ProviderQuery = authentication.ProviderQuery
type PasswordLoginRequest = authentication.PasswordLoginRequest
type BeginFederatedLoginRequest = authentication.BeginFederatedLoginRequest
type CompleteFederatedLoginRequest = authentication.CompleteFederatedLoginRequest
type FederatedLoginCompletion = authentication.FederatedLoginCompletion
type VerifyOTPRequest = authentication.VerifyOTPRequest
type RefreshRequest = authentication.RefreshRequest
type LogoutRequest = authentication.LogoutRequest
type CurrentSessionRequest = authentication.CurrentSessionRequest
type ExchangeAuthorizationCodeRequest = authentication.ExchangeAuthorizationCodeRequest
type SessionView = authentication.SessionView
type Authentication = authentication.Authentication
type ChangePasswordRequest = authentication.ChangePasswordRequest
type ResetPasswordRequest = authentication.ResetPasswordRequest
type RevokeSessionsRequest = authentication.RevokeSessionsRequest
type CredentialManager = authentication.CredentialManager
type VerifyTokenRequest = authentication.VerifyTokenRequest
type VerifiedToken = authentication.VerifiedToken
type TokenVerifier = authentication.TokenVerifier

type Authorization = authorization.Authorization
type AccessBundleRequest = authorization.AccessBundleRequest
type DecisionRequest = authorization.DecisionRequest
type AccessRequest = authorization.AccessRequest
type AccessDecision = authorization.AccessDecision
type AccessReason = authorization.AccessReason
type GrantSource = authorization.GrantSource
type AccessBundle = authorization.AccessBundle
type Subject = authorization.Subject
type FunctionGrant = authorization.FunctionGrant
type Effect = authorization.Effect
type DataPolicy = authorization.DataPolicy
type FieldPolicy = authorization.FieldPolicy
type FieldRule = authorization.FieldRule
type FieldEffect = authorization.FieldEffect
type MaskStrategy = authorization.MaskStrategy
type MaskType = authorization.MaskType
type ReferencePolicy = authorization.ReferencePolicy
type ExportMode = authorization.ExportMode
type ExportPolicy = authorization.ExportPolicy
type Guardrail = authorization.Guardrail
type ExecutionGrant = authorization.ExecutionGrant
type Predicate = authorization.Predicate
type RelationSegment = authorization.RelationSegment
type RelationDirection = authorization.RelationDirection
type Operator = authorization.Operator
type ResourceFacts = authorization.ResourceFacts
type ApplicationRef = authorization.ApplicationRef
type AuthorizationCatalog = authorization.AuthorizationCatalog
type ResourceDefinition = authorization.ResourceDefinition
type ReferenceDefinition = authorization.ReferenceDefinition
type ReferenceTargetAuthority = authorization.ReferenceTargetAuthority
type ActionDefinition = authorization.ActionDefinition
type CatalogReceipt = authorization.CatalogReceipt
type CatalogClient = authorization.CatalogClient
type OrganizationScopes = authorization.OrganizationScopes
type Principal = authorization.Principal
type RequestIdentity = authorization.RequestIdentity
type PrincipalAuthenticator = authorization.PrincipalAuthenticator
type PrincipalResolver = authorization.PrincipalResolver
type PrincipalResolutionRequest = authorization.PrincipalResolutionRequest
type PrincipalResolution = authorization.PrincipalResolution

var ValidateIdentifier = identitymodel.ValidateIdentifier
var WithRequestIdentity = authorization.WithRequestIdentity
var RequestIdentityFromContext = authorization.RequestIdentityFromContext
var PrincipalFromContext = authorization.PrincipalFromContext
var DeriveExecutionAccess = authorization.DeriveExecutionAccess
var RestrictAccess = authorization.RestrictAccess

const (
	ReferenceTargetApplication = authorization.ReferenceTargetApplication
	ReferenceTargetIdentity    = authorization.ReferenceTargetIdentity
	IdentityUserResource       = authorization.IdentityUserResource
	IdentityDepartmentResource = authorization.IdentityDepartmentResource
	UserStatusActive           = identitymodel.UserStatusActive
)
