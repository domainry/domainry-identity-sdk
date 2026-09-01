// Package identity is the cohesive SDK facade. Domain contracts are owned by
// the authentication, authorization, and identity subpackages; this root
// package composes them into one deployment-neutral Binding.
package identity

import (
	"context"
	"time"

	actioncontract "github.com/domainry/domainry-foundation/action"
	"github.com/domainry/domainry-foundation/modulecapability"
	"github.com/domainry/domainry-identity-sdk/authentication"
	"github.com/domainry/domainry-identity-sdk/authorization"
	identitymodel "github.com/domainry/domainry-identity-sdk/identity"
	"github.com/domainry/domainry-identity-sdk/modulehost"
)

type DeploymentMode string

const (
	DeploymentModeModule DeploymentMode = "module"
	DeploymentModeSaaS   DeploymentMode = "saas"
)

type Descriptor struct {
	ProtocolVersion      string         `json:"protocol_version"`
	BundleVersion        string         `json:"bundle_version"`
	AuthorizationVersion string         `json:"authorization_version"`
	Mode                 DeploymentMode `json:"mode"`
	Issuer               string         `json:"issuer,omitempty"`
	Audience             string         `json:"audience,omitempty"`
	Capabilities         []string       `json:"capabilities"`
}

// Binding is the sole deployment-neutral Runtime dependency. An in-process
// module and the remote SaaS adapter expose the same cohesive capabilities.
type Binding interface {
	modulecapability.Binding
	Descriptor() Descriptor
	Authentication() Authentication
	Tokens() TokenVerifier
	Authorization() Authorization
	Principals() PrincipalResolver
	Directory() Directory
	Applications() ApplicationRegistry
	Permissions() PermissionRegistry
	Credentials() CredentialManager
	Close(context.Context) error
}

type Factory interface {
	Open(context.Context, ApplicationRef) (Binding, error)
}

// PermissionUsageProviderBinder is implemented only by an embedded Identity
// module. The host binds its live Action registry projection after composing
// all Runtime and module Actions. Remote Identity queries the same contract
// over HTTP and therefore does not implement this in-process capability.
type PermissionUsageProviderBinder interface {
	BindPermissionUsageProvider(actioncontract.PermissionUsageProvider) error
}

// DatabaseHandle is a project-owned database pool borrowed by an in-process
// Identity module. The provider retains lifecycle ownership; consumers must
// never close DB.
type DatabaseHandle struct {
	Pool                      any
	Driver                    string
	Schema                    string
	FilePath                  string
	OrganizationScopeResolver OrganizationScopeResolver
	BusinessProfileResolver   BusinessProfileResolver
	Migrations                EmbeddedMigrationRegistrar
}

// EmbeddedMigrationRegistrar lets an in-process Identity module execute its
// source-owned schema assembly under the embedding host's migration lock and
// sole _schema_migrations ledger.
type EmbeddedMigrationRegistrar interface {
	ApplyOwnedMigration(context.Context, string, uint, string, string, func(context.Context) error) error
}

// OrganizationScopeResolver projects application-owned organization facts for
// Identity principals. The embedding application supplies the implementation;
// Identity never reads application business tables directly.
type OrganizationScopeResolver func(context.Context, string, []string) (OrganizationScopes, error)

// BusinessProfileBinding is an application-owned active profile fact. Identity
// uses it only to reconcile published system-managed business roles; it never
// reads application business tables directly.
type BusinessProfileBinding struct {
	BindingKey string `json:"binding_key"`
	ProfileID  string `json:"profile_id"`
}

// BusinessProfileResolver projects active application profiles for one
// Identity user. The embedding Runtime remains authoritative for profile
// status, cardinality, and the identity relation.
type BusinessProfileResolver func(context.Context, string, string) ([]BusinessProfileBinding, error)

// DatabaseFactory is implemented by in-process factories that can join the
// embedding Runtime's project database pool. Remote factories intentionally
// implement only Factory.
type DatabaseFactory interface {
	OpenWithDatabase(context.Context, ApplicationRef, DatabaseHandle) (Binding, error)
}

// BootstrapBinding is the deliberately narrow in-process surface available
// before the first tenant exists. It can participate in the host-owned atomic
// tenant transaction, but exposes no authentication or business APIs.
type BootstrapBinding interface {
	modulehost.WorkspaceProvisioner
	Close(context.Context) error
}

// BootstrapDatabaseFactory is implemented only by an embedded Identity
// module. A host uses it to create the first tenant in its project database,
// then closes it and reopens the ordinary workspace-bound Binding.
type BootstrapDatabaseFactory interface {
	OpenBootstrapWithDatabase(context.Context, ApplicationKey, DatabaseHandle) (BootstrapBinding, error)
}

type Clock interface {
	Now() time.Time
}

const (
	ProtocolVersionV1               = "domainry-identity-protocol-v1"
	ProtocolVersionV2               = "domainry-identity-protocol-v2"
	CurrentProtocolVersion          = ProtocolVersionV2
	PolicyBundleVersionV1           = authorization.PolicyBundleVersionV1
	PolicyBundleVersionV2           = authorization.PolicyBundleVersionV2
	PolicyBundleVersionV3           = authorization.PolicyBundleVersionV3
	PolicyBundleVersionV4           = authorization.PolicyBundleVersionV4
	CurrentPolicyBundleVersion      = authorization.CurrentPolicyBundleVersion
	AuthorizationContractVersionV1  = authorization.AuthorizationContractVersionV1
	PrincipalContextContractVersion = authorization.PrincipalContextContractVersion
	EffectAllow                     = authorization.EffectAllow
	EffectDeny                      = authorization.EffectDeny
	DataActionRead                  = authorization.DataActionRead
	DataActionWrite                 = authorization.DataActionWrite
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
type DataAction = authorization.DataAction
type AuthorizationRevision = identitymodel.AuthorizationRevision
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
type ApplicationServiceGrant = authentication.ApplicationServiceGrant
type ExchangeApplicationServiceTokenRequest = authentication.ExchangeApplicationServiceTokenRequest
type ApplicationServiceToken = authentication.ApplicationServiceToken
type VerifyApplicationServiceTokenRequest = authentication.VerifyApplicationServiceTokenRequest
type ApplicationServicePrincipal = authentication.ApplicationServicePrincipal
type ApplicationServiceTokenVerifier = authentication.ApplicationServiceTokenVerifier
type ApplicationServiceAuthentication = authentication.ApplicationServiceAuthentication

// ApplicationServiceVerificationBinding is the narrow resource-service
// capability for verifying already-issued short-lived service tokens.
type ApplicationServiceVerificationBinding interface {
	ApplicationServiceVerifier() ApplicationServiceTokenVerifier
}

// ApplicationServiceBinding is the full Identity service-token capability.
// It is exposed only where both credential exchange and token verification are
// implemented.
type ApplicationServiceBinding interface {
	ApplicationServices() ApplicationServiceAuthentication
}
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
type ApplicationRegistration = authorization.ApplicationRegistration
type ApplicationRegistrationReceipt = authorization.ApplicationRegistrationReceipt
type ApplicationRegistry = authorization.ApplicationRegistry
type PermissionDefinition = authorization.PermissionDefinition
type PermissionReconcileRequest = authorization.PermissionReconcileRequest
type PermissionReconcileReceipt = authorization.PermissionReconcileReceipt
type PermissionRegistry = authorization.PermissionRegistry
type PermissionSourceSnapshotRequest = authorization.PermissionSourceSnapshotRequest
type PermissionSourceSnapshot = authorization.PermissionSourceSnapshot
type PermissionSnapshotReader = authorization.PermissionSnapshotReader

func NewPermissionReconcileRequest(application ApplicationRef, sourceOwner, previousSnapshotHash string, definitions []PermissionDefinition) (PermissionReconcileRequest, error) {
	return authorization.NewPermissionReconcileRequest(application, sourceOwner, previousSnapshotHash, definitions)
}

func PermissionSnapshotHash(sourceOwner string, definitions []PermissionDefinition) (string, error) {
	return authorization.PermissionSnapshotHash(sourceOwner, definitions)
}

type ProjectRoleDefinition = authorization.ProjectRoleDefinition
type ProjectRoleCatalog = authorization.ProjectRoleCatalog
type ProjectRoleCatalogReceipt = authorization.ProjectRoleCatalogReceipt
type ProjectRoleCatalogPublisher = authorization.ProjectRoleCatalogPublisher
type EmbeddedTransaction = modulehost.Transaction
type WorkspaceProvisionFailureInjector = modulehost.WorkspaceProvisionFailureInjector
type WorkspaceIdentityProvisionRequest = modulehost.WorkspaceIdentityProvisionRequest
type WorkspaceIdentityProvisionResult = modulehost.WorkspaceIdentityProvisionResult

const (
	WorkspaceProvisionFailureAfterIdentityUser   = modulehost.WorkspaceProvisionFailureAfterIdentityUser
	WorkspaceProvisionFailureAfterIdentityRole   = modulehost.WorkspaceProvisionFailureAfterIdentityRole
	WorkspaceProvisionFailureAfterRoleAssignment = modulehost.WorkspaceProvisionFailureAfterRoleAssignment
	WorkspaceProvisionFailureAfterCredential     = modulehost.WorkspaceProvisionFailureAfterCredential
)

type WorkspaceRoleReconcileRequest = modulehost.WorkspaceRoleReconcileRequest
type WorkspaceRoleReconcileResult = modulehost.WorkspaceRoleReconcileResult
type EmbeddedWorkspaceProvisioner = modulehost.WorkspaceProvisioner
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
	UserStatusActive = identitymodel.UserStatusActive
)
