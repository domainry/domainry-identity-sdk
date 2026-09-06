package modulehost

import "context"

const (
	InstallationAdministratorBootstrapContractVersionV1      = "domainry-installation-administrator-bootstrap-v1"
	InstallationAdministratorBootstrapContractCanonicalV1    = "domainry-installation-administrator-bootstrap-v1|request:invocation_id,workspace_id,login_id,name|authority:embedded_host_explicit_config|role:tenant_admin|scope:initial_workspace_company|cardinality:first_only|transaction:host_owned|audit:assignment_and_delivery|result:receipt_only|completion:committed,rolled_back|credential:post_commit_one_time_nonpersistent|delivery:acknowledged"
	InstallationAdministratorBootstrapContractHashV1         = "30fbfdd92ae68dd93f90f5028d42a3ab8b58bb0363c2740124e4f950c73968b7"
	CurrentInstallationAdministratorBootstrapContractVersion = InstallationAdministratorBootstrapContractVersionV1
	CurrentInstallationAdministratorBootstrapContractHash    = InstallationAdministratorBootstrapContractHashV1
)

// InstallationAdministratorBootstrapRequest is accepted only by the embedded
// module. The host derives WorkspaceID from Runtime's installation authority;
// no browser, Handler, or serialized request can select it or the fixed role.
type InstallationAdministratorBootstrapRequest struct {
	ContractVersion string `json:"-"`
	ContractHash    string `json:"-"`
	InvocationID    string `json:"-"`
	WorkspaceID     string `json:"-"`
	LoginID         string `json:"-"`
	Name            string `json:"-"`
}

type InstallationAdministratorBootstrapReceipt struct {
	ContractVersion     string `json:"-"`
	ContractHash        string `json:"-"`
	ReceiptID           string `json:"-"`
	InvocationID        string `json:"-"`
	WorkspaceID         string `json:"-"`
	UserID              string `json:"-"`
	LoginID             string `json:"-"`
	RoleKey             string `json:"-"`
	Replayed            bool   `json:"-"`
	CredentialClaimed   bool   `json:"-"`
	CredentialDelivered bool   `json:"-"`
}

type InstallationAdministratorBootstrapCompletion struct {
	WorkspaceID string                                       `json:"-"`
	ReceiptID   string                                       `json:"-"`
	Outcome     WorkspaceIdentityBootstrapTransactionOutcome `json:"-"`
}

type InstallationAdministratorCredentialClaim struct {
	WorkspaceID string `json:"-"`
	ReceiptID   string `json:"-"`
}

type InstallationAdministratorOneTimeCredential struct {
	LoginID            string `json:"-"`
	InitialPassword    string `json:"-"`
	MustChangePassword bool   `json:"-"`
}

type InstallationAdministratorCredentialDeliveryAcknowledgment struct {
	WorkspaceID string `json:"-"`
	ReceiptID   string `json:"-"`
}

// InstallationAdministratorBootstrapV1 is a startup-only, fixed-purpose
// capability. It is absent from HTTP and the deployment-neutral Binding.
type InstallationAdministratorBootstrapV1 interface {
	BootstrapInstallationAdministratorV1(context.Context, InstallationAdministratorBootstrapRequest, Transaction) (InstallationAdministratorBootstrapReceipt, error)
	CompleteInstallationAdministratorBootstrapV1(context.Context, InstallationAdministratorBootstrapCompletion) error
	ClaimInstallationAdministratorCredentialV1(context.Context, InstallationAdministratorCredentialClaim) (InstallationAdministratorOneTimeCredential, error)
	AcknowledgeInstallationAdministratorCredentialDeliveryV1(context.Context, InstallationAdministratorCredentialDeliveryAcknowledgment) error
}
