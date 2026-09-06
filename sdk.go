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
	Projection() Projection
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
	Pool                    any
	Driver                  string
	Schema                  string
	FilePath                string
	BusinessProfileResolver BusinessProfileResolver
	Migrations              EmbeddedMigrationRegistrar
	ModuleMigrations        modulehost.MigrationRegistrar
	// WorkspaceIdentityUsageAuthority is a trusted infrastructure-only
	// installation authorization and active Workspace catalog provider. It is
	// never exposed through Binding or accepted from a handler request.
	WorkspaceIdentityUsageAuthority modulehost.WorkspaceIdentityUsageInstallationAuthority
	// WorkspaceIdentityUsageCursorKey is a host-owned stable 32-byte AES key.
	// Identity uses it only for authenticated encryption of usage page cursors.
	// The host must persist it across restarts; deliberate rotation invalidates
	// outstanding cursors fail closed.
	WorkspaceIdentityUsageCursorKey []byte
}

// EmbeddedMigrationRegistrar lets an in-process Identity module execute its
// source-owned schema assembly under the embedding host's migration lock and
// sole _schema_migrations ledger.
type EmbeddedMigrationRegistrar interface {
	ApplyOwnedMigration(context.Context, string, uint, string, string, func(context.Context) error) error
}

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

type ProjectProfileExtension = identitymodel.ProjectProfileExtension
type ProjectBusinessIdentityBinding = identitymodel.ProjectBusinessIdentityBinding
type ProjectProfileClaimBinding = identitymodel.ProjectProfileClaimBinding
type ProjectProfileBindingLifecycle = identitymodel.ProjectProfileBindingLifecycle
type ProjectProfileClaimProof = identitymodel.ProjectProfileClaimProof
type ProjectProfileExtensionPublisher = identitymodel.ProjectProfileExtensionPublisher

// EmbeddedProjectProfileExtensionBinding is optional and implemented by an
// in-process Identity module. Runtime uses it to publish its authoritative
// profile-extension metadata without exposing Identity's metadata store.
type EmbeddedProjectProfileExtensionBinding interface {
	ProjectProfileExtensionPublisher() ProjectProfileExtensionPublisher
}

// DatabaseFactory is implemented by in-process factories that can join the
// embedding Runtime's project database pool. Remote factories intentionally
// implement only Factory.
type DatabaseFactory interface {
	OpenWithDatabase(context.Context, ApplicationRef, DatabaseHandle) (Binding, error)
}

// BootstrapBinding is the deliberately narrow in-process contract available
// before the first Workspace exists. It exposes the trusted bootstrap
// capability, not the earlier role-selectable WorkspaceProvisioner.
type BootstrapBinding interface {
	modulehost.WorkspaceIdentityBootstrap
	BootstrapProjectRoleCatalogBinder
	Close(context.Context) error
}

// BootstrapProjectRoleCatalogBinder supplies the application-owned role
// directory before the first workspace exists. Implementations must keep the
// catalog in memory; workspace role rows are written only by the host-owned
// provisioning transaction.
type BootstrapProjectRoleCatalogBinder interface {
	BindBootstrapProjectRoleCatalog(context.Context, ProjectRoleCatalog) error
}

// BootstrapDatabaseFactory is implemented only by an embedded Identity
// module. A host uses it to create the first Workspace in its project database,
// then closes it and reopens the ordinary workspace-bound Binding.
type BootstrapDatabaseFactory interface {
	OpenBootstrapWithDatabase(context.Context, ApplicationKey, DatabaseHandle) (BootstrapBinding, error)
}

// EmbeddedInstallationAdministratorBootstrapBinding is implemented only by
// an in-process, initialized Identity module. Runtime may use it from explicit
// installation startup configuration; remote and browser bindings never gain
// this authority.
type EmbeddedInstallationAdministratorBootstrapBinding interface {
	InstallationAdministratorBootstrap() modulehost.InstallationAdministratorBootstrapV1
}

type Clock interface {
	Now() time.Time
}

const (
	ProtocolVersionV1                     = "domainry-identity-protocol-v1"
	ProtocolVersionV2                     = "domainry-identity-protocol-v2"
	ProtocolVersionV3                     = "domainry-identity-protocol-v3"
	CurrentProtocolVersion                = ProtocolVersionV3
	PolicyBundleVersionV1                 = authorization.PolicyBundleVersionV1
	PolicyBundleVersionV2                 = authorization.PolicyBundleVersionV2
	PolicyBundleVersionV3                 = authorization.PolicyBundleVersionV3
	PolicyBundleVersionV4                 = authorization.PolicyBundleVersionV4
	PolicyBundleVersionV5                 = authorization.PolicyBundleVersionV5
	CurrentPolicyBundleVersion            = authorization.CurrentPolicyBundleVersion
	AuthorizationContractVersionV1        = authorization.AuthorizationContractVersionV1
	AuthorizationContractVersionV2        = authorization.AuthorizationContractVersionV2
	CurrentAuthorizationContractVersion   = authorization.CurrentAuthorizationContractVersion
	PrincipalContextContractVersion       = authorization.PrincipalContextContractVersion
	EffectAllow                           = authorization.EffectAllow
	EffectDeny                            = authorization.EffectDeny
	ExportModeDeny                        = authorization.ExportModeDeny
	ExportModeAllowList                   = authorization.ExportModeAllowList
	OperatorEqual                         = authorization.OperatorEqual
	OperatorNotEqual                      = authorization.OperatorNotEqual
	OperatorIn                            = authorization.OperatorIn
	OperatorNotIn                         = authorization.OperatorNotIn
	OperatorExists                        = authorization.OperatorExists
	OperatorPrefix                        = authorization.OperatorPrefix
	OperatorContains                      = authorization.OperatorContains
	FieldEffectAllow                      = authorization.FieldEffectAllow
	FieldEffectDeny                       = authorization.FieldEffectDeny
	FieldEffectHide                       = authorization.FieldEffectHide
	FieldEffectMask                       = authorization.FieldEffectMask
	MaskTypePhone                         = authorization.MaskTypePhone
	MaskTypeIDNumber                      = authorization.MaskTypeIDNumber
	MaskTypeEmail                         = authorization.MaskTypeEmail
	MaskTypeYearOnly                      = authorization.MaskTypeYearOnly
	MaskTypeLastN                         = authorization.MaskTypeLastN
	ChallengeStatusPendingDelivery        = authentication.ChallengeStatusPendingDelivery
	ChallengeStatusActive                 = authentication.ChallengeStatusActive
	ChallengeStatusFailed                 = authentication.ChallengeStatusFailed
	ChallengeStatusConsumed               = authentication.ChallengeStatusConsumed
	ChallengeStatusExpired                = authentication.ChallengeStatusExpired
	ChallengeStatusSuperseded             = authentication.ChallengeStatusSuperseded
	AuthenticationStatusAuthenticated     = authentication.AuthenticationStatusAuthenticated
	AuthenticationStatusChallengeRequired = authentication.AuthenticationStatusChallengeRequired
	RelationForward                       = authorization.RelationForward
	RelationReverse                       = authorization.RelationReverse
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
type User = identitymodel.User
type OrganizationUnit = identitymodel.OrganizationUnit
type Role = identitymodel.Role
type UserRoleAssignment = identitymodel.UserRoleAssignment
type ApplicationScope = identitymodel.ApplicationScope
type ProjectionQuery = identitymodel.ProjectionQuery
type UserLookup = identitymodel.UserLookup
type OrganizationUnitLookup = identitymodel.OrganizationUnitLookup
type DisplayNameQuery = identitymodel.DisplayNameQuery
type DisplayName = identitymodel.DisplayName
type DisplayNameResult = identitymodel.DisplayNameResult
type UserRoleAssignmentQuery = identitymodel.UserRoleAssignmentQuery
type Projection = identitymodel.Projection
type DisplayNameProjection = identitymodel.DisplayNameProjection
type HandlerUserOperation = identitymodel.HandlerUserOperation
type HandlerLoginMode = identitymodel.HandlerLoginMode
type HandlerUserMutation = identitymodel.HandlerUserMutation
type HandlerProfileBindingMutation = identitymodel.HandlerProfileBindingMutation
type HandlerDeliveryRequest = identitymodel.HandlerDeliveryRequest
type HandlerProfileBinding = identitymodel.HandlerProfileBinding
type HandlerProfileBindingSelector = identitymodel.HandlerProfileBindingSelector
type HandlerDeliveryResult = identitymodel.HandlerDeliveryResult
type HandlerInitialCredential = identitymodel.HandlerInitialCredential
type HandlerBoundIdentityRequest = identitymodel.HandlerBoundIdentityRequest
type HandlerBoundIdentity = identitymodel.HandlerBoundIdentity
type HandlerDelivery = identitymodel.HandlerDelivery
type StoreOrganizationOperation = identitymodel.StoreOrganizationOperation
type StoreOrganizationMutation = identitymodel.StoreOrganizationMutation
type StoreOrganizationDeliveryRequest = identitymodel.StoreOrganizationDeliveryRequest
type StoreOrganization = identitymodel.StoreOrganization
type StoreOrganizationDeliveryResult = identitymodel.StoreOrganizationDeliveryResult
type StoreOrganizationResolveRequest = identitymodel.StoreOrganizationResolveRequest
type StoreOrganizationListRequest = identitymodel.StoreOrganizationListRequest
type StoreOrganizationPage = identitymodel.StoreOrganizationPage
type StoreOrganizationDelivery = identitymodel.StoreOrganizationDelivery
type WorkspaceIdentityUsageRequest = identitymodel.WorkspaceIdentityUsageRequest
type WorkspaceIdentityUsageResolveRequest = identitymodel.WorkspaceIdentityUsageResolveRequest
type WorkspaceIdentityUsageAuthorizationRequest = identitymodel.WorkspaceIdentityUsageAuthorizationRequest
type WorkspaceIdentityUsageAuthorization = identitymodel.WorkspaceIdentityUsageAuthorization
type WorkspaceIdentityAccountCounts = identitymodel.WorkspaceIdentityAccountCounts
type WorkspaceIdentityUsage = identitymodel.WorkspaceIdentityUsage
type WorkspaceIdentityUsagePage = identitymodel.WorkspaceIdentityUsagePage
type WorkspaceIdentityUsageAggregate = identitymodel.WorkspaceIdentityUsageAggregate

const (
	HandlerDeliveryContractVersionV1             = identitymodel.HandlerDeliveryContractVersionV1
	HandlerDeliveryCreatePermission              = identitymodel.HandlerDeliveryCreatePermission
	HandlerDeliveryUpdatePermission              = identitymodel.HandlerDeliveryUpdatePermission
	HandlerDeliveryDisablePermission             = identitymodel.HandlerDeliveryDisablePermission
	HandlerDeliveryResolvePermission             = identitymodel.HandlerDeliveryResolvePermission
	HandlerUserCreate                            = identitymodel.HandlerUserCreate
	HandlerUserUpdate                            = identitymodel.HandlerUserUpdate
	HandlerUserDisable                           = identitymodel.HandlerUserDisable
	HandlerLoginNone                             = identitymodel.HandlerLoginNone
	HandlerLoginPassword                         = identitymodel.HandlerLoginPassword
	StoreOrganizationDeliveryContractVersionV1   = identitymodel.StoreOrganizationDeliveryContractVersionV1
	StoreOrganizationDefaultPageSize             = identitymodel.StoreOrganizationDefaultPageSize
	StoreOrganizationMaxPageSize                 = identitymodel.StoreOrganizationMaxPageSize
	StoreOrganizationDeliveryCreatePermission    = identitymodel.StoreOrganizationDeliveryCreatePermission
	StoreOrganizationDeliveryRenamePermission    = identitymodel.StoreOrganizationDeliveryRenamePermission
	StoreOrganizationDeliveryDisablePermission   = identitymodel.StoreOrganizationDeliveryDisablePermission
	StoreOrganizationDeliveryResolvePermission   = identitymodel.StoreOrganizationDeliveryResolvePermission
	StoreOrganizationDeliveryListPermission      = identitymodel.StoreOrganizationDeliveryListPermission
	StoreOrganizationCreate                      = identitymodel.StoreOrganizationCreate
	StoreOrganizationRename                      = identitymodel.StoreOrganizationRename
	StoreOrganizationDisable                     = identitymodel.StoreOrganizationDisable
	WorkspaceIdentityUsageContractVersionV1      = identitymodel.WorkspaceIdentityUsageContractVersionV1
	WorkspaceIdentityUsageContractVersionV2      = identitymodel.WorkspaceIdentityUsageContractVersionV2
	WorkspaceIdentityUsageContractVersionV3      = identitymodel.WorkspaceIdentityUsageContractVersionV3
	CurrentWorkspaceIdentityUsageContractVersion = identitymodel.CurrentWorkspaceIdentityUsageContractVersion
	WorkspaceIdentityUsageContractHashV2         = identitymodel.WorkspaceIdentityUsageContractHashV2
	WorkspaceIdentityUsageContractHashV3         = identitymodel.WorkspaceIdentityUsageContractHashV3
	CurrentWorkspaceIdentityUsageContractHash    = identitymodel.CurrentWorkspaceIdentityUsageContractHash
	WorkspaceIdentityUsageAggregatePermission    = identitymodel.WorkspaceIdentityUsageAggregatePermission
	WorkspaceIdentityUsageDefaultPageSize        = identitymodel.WorkspaceIdentityUsageDefaultPageSize
	WorkspaceIdentityUsageMaxPageSize            = identitymodel.WorkspaceIdentityUsageMaxPageSize
)

// HandlerDeliveryBinding is optional so protocol-v3 providers that predate
// handler delivery remain source compatible and fail capability discovery
// explicitly instead of silently emulating a non-atomic workflow.
type HandlerDeliveryBinding interface {
	HandlerDelivery() HandlerDelivery
}

// HandlerDeliveryUnitOfWorkBinder is an infrastructure-only bridge. Runtime
// binds Identity to the Action transaction, then injects only the returned
// narrow HandlerDelivery into generated project code. A project handler never
// receives EmbeddedTransaction, its executor, or a database handle.
type HandlerDeliveryUnitOfWorkBinder interface {
	BindHandlerDeliveryUnitOfWork(EmbeddedTransaction) (HandlerDelivery, error)
}

type EmbeddedHandlerDeliveryBinding interface {
	HandlerDeliveryUnitOfWorkBinder() HandlerDeliveryUnitOfWorkBinder
}

// StoreOrganizationDeliveryBinding is available on the deployment-neutral
// core. Embedded Runtime integrations must use the UoW binder below.
type StoreOrganizationDeliveryBinding interface {
	StoreOrganizationDelivery() StoreOrganizationDelivery
}

type StoreOrganizationDeliveryUnitOfWorkBinder interface {
	BindStoreOrganizationDeliveryUnitOfWork(EmbeddedTransaction) (StoreOrganizationDelivery, error)
}

type EmbeddedStoreOrganizationDeliveryBinding interface {
	StoreOrganizationDeliveryUnitOfWorkBinder() StoreOrganizationDeliveryUnitOfWorkBinder
}

// WorkspaceIdentityUsageUnitOfWorkBinder is the only public discovery surface
// for this embedded capability. The unbound aggregate is never exposed.
type WorkspaceIdentityUsageUnitOfWorkBinder interface {
	AuthorizeWorkspaceIdentityUsage(context.Context, WorkspaceIdentityUsageAuthorizationRequest) (WorkspaceIdentityUsageAuthorization, error)
	BindWorkspaceIdentityUsageUnitOfWork(EmbeddedTransaction) (WorkspaceIdentityUsageAggregate, error)
}

type EmbeddedWorkspaceIdentityUsageBinding interface {
	WorkspaceIdentityUsageUnitOfWorkBinder() WorkspaceIdentityUsageUnitOfWorkBinder
}

type AuthSession = authentication.AuthSession
type Provider = authentication.Provider
type ProviderChallenge = authentication.ProviderChallenge
type ChallengeStatus = authentication.ChallengeStatus
type AuthenticationStatus = authentication.AuthenticationStatus
type AuthenticationOutcome = authentication.AuthenticationOutcome
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
type ChallengeAuthentication = authentication.ChallengeAuthentication
type ChangePasswordRequest = authentication.ChangePasswordRequest
type ResetPasswordRequest = authentication.ResetPasswordRequest
type RevokeSessionsRequest = authentication.RevokeSessionsRequest
type CredentialManager = authentication.CredentialManager
type BeginActionAssuranceRequest = authentication.BeginActionAssuranceRequest
type VerifyActionAssuranceRequest = authentication.VerifyActionAssuranceRequest
type ActionAssuranceReceipt = authentication.ActionAssuranceReceipt
type ValidateActionAssuranceReceiptRequest = authentication.ValidateActionAssuranceReceiptRequest
type ActionAssurance = authentication.ActionAssurance
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

// ChallengeAuthenticationBinding exposes protocol-v3 challenge-aware login
// without forcing legacy test/resource bindings to implement it.
type ChallengeAuthenticationBinding interface {
	ChallengeAuthentication() ChallengeAuthentication
}

// SecurityChallengeDeliveryBinder is implemented by an embedded Identity
// module. Runtime binds the already-open Integration Operations capability;
// Identity never receives provider credentials.
type SecurityChallengeDeliveryBinder interface {
	BindSecurityChallengeDelivery(modulehost.SecurityChallengeDelivery) error
}

// ActionAssuranceBinding exposes Identity-owned OTP verification to Runtime.
// Runtime remains the owner of payload-bound, one-time Action grants.
type ActionAssuranceBinding interface {
	ActionAssurance() ActionAssurance
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
type ProjectRolePermission = authorization.ProjectRolePermission
type DataScope = authorization.DataScope
type ProjectRoleCatalog = authorization.ProjectRoleCatalog
type ProjectRoleCatalogReceipt = authorization.ProjectRoleCatalogReceipt
type ProjectRoleCatalogPublisher = authorization.ProjectRoleCatalogPublisher

// WorkspaceBootstrapProjectRoleCatalogSHA256 is the shared canonical digest
// used by Runtime and Identity for the trusted Workspace bootstrap role policy.
func WorkspaceBootstrapProjectRoleCatalogSHA256(catalog ProjectRoleCatalog) (string, error) {
	return authorization.WorkspaceBootstrapProjectRoleCatalogSHA256(catalog)
}

const (
	DataScopeAll       = authorization.DataScopeAll
	DataScopeOwner     = authorization.DataScopeOwner
	DataScopeOrg       = authorization.DataScopeOrg
	DataScopeOrgChild  = authorization.DataScopeOrgChild
	DataScopeTargetOrg = authorization.DataScopeTargetOrg
)

var DataScopeValues = authorization.DataScopeValues

type EmbeddedTransaction = modulehost.Transaction
type EmbeddedTransactionExecutor = modulehost.TransactionExecutor
type WorkspaceProvisionFailureInjector = modulehost.WorkspaceProvisionFailureInjector
type WorkspaceIdentityProvisionRequest = modulehost.WorkspaceIdentityProvisionRequest
type WorkspaceAcceptanceOrganization = modulehost.WorkspaceAcceptanceOrganization
type WorkspaceAcceptanceActor = modulehost.WorkspaceAcceptanceActor
type WorkspaceIdentityProvisionResult = modulehost.WorkspaceIdentityProvisionResult
type WorkspaceIdentityBootstrapRequest = modulehost.WorkspaceIdentityBootstrapRequest
type WorkspaceIdentityBootstrapReceipt = modulehost.WorkspaceIdentityBootstrapReceipt
type WorkspaceIdentityBootstrap = modulehost.WorkspaceIdentityBootstrap
type WorkspaceIdentityBootstrapCredentialClaim = modulehost.WorkspaceIdentityBootstrapCredentialClaim
type WorkspaceIdentityBootstrapOneTimeCredential = modulehost.WorkspaceIdentityBootstrapOneTimeCredential
type WorkspaceIdentityBootstrapTransactionOutcome = modulehost.WorkspaceIdentityBootstrapTransactionOutcome
type WorkspaceIdentityBootstrapCompletion = modulehost.WorkspaceIdentityBootstrapCompletion

const (
	WorkspaceProvisionFailureAfterIdentityUser      = modulehost.WorkspaceProvisionFailureAfterIdentityUser
	WorkspaceProvisionFailureAfterIdentityRole      = modulehost.WorkspaceProvisionFailureAfterIdentityRole
	WorkspaceProvisionFailureAfterRoleAssignment    = modulehost.WorkspaceProvisionFailureAfterRoleAssignment
	WorkspaceProvisionFailureAfterCredential        = modulehost.WorkspaceProvisionFailureAfterCredential
	WorkspaceProvisionFailureAfterCompany           = modulehost.WorkspaceProvisionFailureAfterCompany
	WorkspaceProvisionFailureAfterFirstStore        = modulehost.WorkspaceProvisionFailureAfterFirstStore
	WorkspaceProvisionFailureAfterBootstrapReceipt  = modulehost.WorkspaceProvisionFailureAfterBootstrapReceipt
	WorkspaceIdentityBootstrapContractVersion       = modulehost.WorkspaceIdentityBootstrapContractVersion
	WorkspaceIdentityBootstrapContractCanonical     = modulehost.WorkspaceIdentityBootstrapContractCanonical
	WorkspaceIdentityBootstrapContractHash          = modulehost.WorkspaceIdentityBootstrapContractHash
	WorkspaceIdentityBootstrapTransactionCommitted  = modulehost.WorkspaceIdentityBootstrapTransactionCommitted
	WorkspaceIdentityBootstrapTransactionRolledBack = modulehost.WorkspaceIdentityBootstrapTransactionRolledBack
)

type WorkspaceRoleReconcileRequest = modulehost.WorkspaceRoleReconcileRequest
type WorkspaceRoleReconcileResult = modulehost.WorkspaceRoleReconcileResult
type EmbeddedWorkspaceProvisioner = modulehost.WorkspaceProvisioner
type WorkspaceAcceptanceFixtureRequest = modulehost.WorkspaceAcceptanceFixtureRequest
type EmbeddedWorkspaceAcceptanceFixtureProvisioner = modulehost.WorkspaceAcceptanceFixtureProvisioner
type EmbeddedWorkspaceAcceptanceFixtureProvisionerBinding = modulehost.WorkspaceAcceptanceFixtureProvisionerBinding
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
