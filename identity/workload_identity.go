package identity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
)

const WorkflowWorkloadSubjectPrefix = "workflow:"

const (
	WorkflowWorkloadBindingActive   = "active"
	WorkflowWorkloadBindingInactive = "inactive"
)

type WorkflowWorkloadBindingSpec struct {
	WorkflowKey         string   `json:"workflow_key"`
	DefinitionVersionID string   `json:"definition_version_id"`
	DefinitionVersion   int      `json:"definition_version"`
	RoleKey             string   `json:"role_key"`
	ActionKeys          []string `json:"action_keys"`
}

type ApplyWorkflowWorkloadBindingsRequest struct {
	Application   ApplicationScope              `json:"application"`
	ReleaseID     string                        `json:"release_id"`
	ReleaseDigest string                        `json:"release_digest"`
	Bindings      []WorkflowWorkloadBindingSpec `json:"bindings"`
}

type WorkflowWorkloadBinding struct {
	Application         ApplicationScope `json:"application"`
	SubjectID           SubjectID        `json:"subject_id"`
	WorkflowKey         string           `json:"workflow_key"`
	DefinitionVersionID string           `json:"definition_version_id"`
	DefinitionVersion   int              `json:"definition_version"`
	RoleKey             string           `json:"role_key"`
	ActionKeys          []string         `json:"action_keys"`
	ReleaseID           string           `json:"release_id"`
	ReleaseDigest       string           `json:"release_digest"`
	SourceKind          string           `json:"source_kind"`
	SourceID            string           `json:"source_id"`
	Status              string           `json:"status"`
	CreatedAt           string           `json:"created_at"`
	UpdatedAt           string           `json:"updated_at"`
	DeactivatedAt       string           `json:"deactivated_at,omitempty"`
}

type ApplyWorkflowWorkloadBindingsResult struct {
	Bindings []WorkflowWorkloadBinding `json:"bindings"`
}

type GetWorkflowWorkloadBindingRequest struct {
	Application         ApplicationScope `json:"application"`
	WorkflowKey         string           `json:"workflow_key"`
	DefinitionVersionID string           `json:"definition_version_id"`
	ReleaseDigest       string           `json:"release_digest"`
}

// WorkflowWorkloadIdentity is a release control-plane capability. Apply
// replaces the complete active set for one application and release atomically.
type WorkflowWorkloadIdentity interface {
	ApplyWorkflowWorkloadBindings(context.Context, ApplyWorkflowWorkloadBindingsRequest) (ApplyWorkflowWorkloadBindingsResult, error)
	GetWorkflowWorkloadBinding(context.Context, GetWorkflowWorkloadBindingRequest) (WorkflowWorkloadBinding, error)
}

type WorkflowWorkloadIdentityBinding interface {
	WorkflowWorkloads() WorkflowWorkloadIdentity
}

func WorkflowWorkloadSubjectID(workflowKey string) SubjectID {
	workflowKey = strings.TrimSpace(workflowKey)
	if workflowKey == "" {
		return ""
	}
	return SubjectID(WorkflowWorkloadSubjectPrefix + workflowKey)
}

func WorkflowWorkloadReleaseDigest(bindings []WorkflowWorkloadBindingSpec) (string, error) {
	canonical := make([]WorkflowWorkloadBindingSpec, len(bindings))
	for index, binding := range bindings {
		canonical[index] = binding
		canonical[index].WorkflowKey = strings.TrimSpace(binding.WorkflowKey)
		canonical[index].DefinitionVersionID = strings.TrimSpace(binding.DefinitionVersionID)
		canonical[index].RoleKey = strings.TrimSpace(binding.RoleKey)
		canonical[index].ActionKeys = append([]string(nil), binding.ActionKeys...)
		for actionIndex := range canonical[index].ActionKeys {
			canonical[index].ActionKeys[actionIndex] = strings.TrimSpace(canonical[index].ActionKeys[actionIndex])
		}
		sort.Strings(canonical[index].ActionKeys)
	}
	sort.Slice(canonical, func(left, right int) bool { return canonical[left].WorkflowKey < canonical[right].WorkflowKey })
	payload, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:]), nil
}

func WorkflowWorkloadReleaseID(digest string) string {
	return "workflow-release:" + strings.TrimSpace(digest)
}

func (request ApplyWorkflowWorkloadBindingsRequest) Validate() error {
	if !request.Application.WorkspaceID.Valid() || !request.Application.ApplicationKey.Valid() || strings.TrimSpace(request.ReleaseID) == "" || strings.TrimSpace(request.ReleaseDigest) == "" {
		return &Error{StatusCode: http.StatusBadRequest, Code: "identity.workflow_workload_release_invalid"}
	}
	seen := make(map[string]struct{}, len(request.Bindings))
	for index := range request.Bindings {
		binding := &request.Bindings[index]
		binding.WorkflowKey = strings.TrimSpace(binding.WorkflowKey)
		binding.DefinitionVersionID = strings.TrimSpace(binding.DefinitionVersionID)
		binding.RoleKey = strings.TrimSpace(binding.RoleKey)
		if binding.WorkflowKey == "" || binding.DefinitionVersionID == "" || binding.DefinitionVersion <= 0 || binding.RoleKey == "" || len(binding.ActionKeys) == 0 {
			return &Error{StatusCode: http.StatusBadRequest, Code: "identity.workflow_workload_binding_invalid"}
		}
		if _, duplicate := seen[binding.WorkflowKey]; duplicate {
			return &Error{StatusCode: http.StatusBadRequest, Code: "identity.workflow_workload_binding_duplicate"}
		}
		seen[binding.WorkflowKey] = struct{}{}
		actions := make(map[string]struct{}, len(binding.ActionKeys))
		for _, actionKey := range binding.ActionKeys {
			actionKey = strings.TrimSpace(actionKey)
			if actionKey == "" {
				return &Error{StatusCode: http.StatusBadRequest, Code: "identity.workflow_workload_action_invalid"}
			}
			if _, duplicate := actions[actionKey]; duplicate {
				return &Error{StatusCode: http.StatusBadRequest, Code: "identity.workflow_workload_action_duplicate"}
			}
			actions[actionKey] = struct{}{}
		}
		binding.ActionKeys = binding.ActionKeys[:0]
		for actionKey := range actions {
			binding.ActionKeys = append(binding.ActionKeys, actionKey)
		}
		sort.Strings(binding.ActionKeys)
	}
	sort.Slice(request.Bindings, func(left, right int) bool {
		return request.Bindings[left].WorkflowKey < request.Bindings[right].WorkflowKey
	})
	digest, err := WorkflowWorkloadReleaseDigest(request.Bindings)
	if err != nil {
		return &Error{StatusCode: http.StatusBadRequest, Code: "identity.workflow_workload_release_invalid", Cause: err}
	}
	if strings.TrimSpace(request.ReleaseDigest) != digest || strings.TrimSpace(request.ReleaseID) != WorkflowWorkloadReleaseID(digest) {
		return &Error{StatusCode: http.StatusConflict, Code: "identity.workflow_workload_release_digest_mismatch"}
	}
	return nil
}

func (request GetWorkflowWorkloadBindingRequest) Validate() error {
	if !request.Application.WorkspaceID.Valid() || !request.Application.ApplicationKey.Valid() || strings.TrimSpace(request.WorkflowKey) == "" || strings.TrimSpace(request.DefinitionVersionID) == "" || strings.TrimSpace(request.ReleaseDigest) == "" {
		return &Error{StatusCode: http.StatusBadRequest, Code: "identity.workflow_workload_lookup_invalid"}
	}
	return nil
}
