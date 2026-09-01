package authorization

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
)

type PermissionDefinition struct {
	PermissionKey string `json:"permission_key"`
	ResourceKey   string `json:"resource_key"`
	ActionKey     string `json:"action_key"`
	Label         string `json:"label"`
	Description   string `json:"description,omitempty"`
	Category      string `json:"category"`
	SourceKind    string `json:"source_kind"`
}

type PermissionReconcileRequest struct {
	Application          ApplicationRef         `json:"application"`
	SourceOwner          string                 `json:"source_owner"`
	PreviousSnapshotHash string                 `json:"previous_snapshot_hash,omitempty"`
	SnapshotHash         string                 `json:"snapshot_hash"`
	Definitions          []PermissionDefinition `json:"definitions"`
}

type PermissionReconcileReceipt struct {
	WorkspaceID          WorkspaceID `json:"workspace_id"`
	SourceOwner          string      `json:"source_owner"`
	PreviousSnapshotHash string      `json:"previous_snapshot_hash,omitempty"`
	SnapshotHash         string      `json:"snapshot_hash"`
	DefinitionCount      int         `json:"definition_count"`
	Inserted             int         `json:"inserted"`
	Updated              int         `json:"updated"`
	Retired              int         `json:"retired"`
	Unchanged            int         `json:"unchanged"`
}

type PermissionSourceSnapshotRequest struct {
	Application ApplicationRef `json:"application"`
	SourceOwner string         `json:"source_owner"`
}

func (request PermissionSourceSnapshotRequest) ValidateContract() error {
	if !request.Application.WorkspaceID.Valid() || !request.Application.ApplicationKey.Valid() {
		return &Error{Code: "identity.permission_snapshot_scope_invalid"}
	}
	if !validSourceOwner(request.SourceOwner) {
		return &Error{Code: "identity.permission_source_owner_invalid"}
	}
	return nil
}

type PermissionSourceSnapshot struct {
	WorkspaceID  WorkspaceID            `json:"workspace_id"`
	SourceOwner  string                 `json:"source_owner"`
	SnapshotHash string                 `json:"snapshot_hash,omitempty"`
	Definitions  []PermissionDefinition `json:"definitions,omitempty"`
}

func (snapshot PermissionSourceSnapshot) ValidateFor(request PermissionSourceSnapshotRequest) error {
	if err := request.ValidateContract(); err != nil {
		return err
	}
	hash := strings.TrimSpace(snapshot.SnapshotHash)
	if snapshot.WorkspaceID != request.Application.WorkspaceID ||
		strings.TrimSpace(snapshot.SourceOwner) != strings.TrimSpace(request.SourceOwner) ||
		hash != "" && !validPermissionSnapshotHash(hash) || hash == "" && len(snapshot.Definitions) != 0 {
		return &Error{Code: "identity.permission_source_snapshot_invalid"}
	}
	if hash != "" {
		computed, err := PermissionSnapshotHash(request.SourceOwner, snapshot.Definitions)
		if err != nil || computed != hash {
			return &Error{Code: "identity.permission_source_snapshot_invalid"}
		}
	}
	return nil
}

// ValidateFor proves that a successful reconcile response acknowledges the
// exact workspace, owner and immutable definition snapshot submitted by the
// caller. Identity may report the submitted previous hash or the new snapshot
// hash when an idempotent retry observes that snapshot already applied.
func (receipt PermissionReconcileReceipt) ValidateFor(request PermissionReconcileRequest) error {
	if err := request.ValidateContract(); err != nil {
		return err
	}
	previousMatches := receipt.PreviousSnapshotHash == request.PreviousSnapshotHash || receipt.PreviousSnapshotHash == request.SnapshotHash
	if receipt.WorkspaceID != request.Application.WorkspaceID ||
		strings.TrimSpace(receipt.SourceOwner) != request.SourceOwner ||
		strings.TrimSpace(receipt.SnapshotHash) != request.SnapshotHash ||
		receipt.DefinitionCount != len(request.Definitions) || !previousMatches ||
		receipt.Inserted < 0 || receipt.Updated < 0 || receipt.Retired < 0 || receipt.Unchanged < 0 {
		return &Error{Code: "identity.permission_reconcile_receipt_invalid"}
	}
	return nil
}

type PermissionRegistry interface {
	Reconcile(context.Context, PermissionReconcileRequest) (PermissionReconcileReceipt, error)
}

// PermissionSnapshotReader is the authoritative CAS baseline query for one
// source owner. It is separate from PermissionRegistry so command-only test
// doubles and hosts do not accidentally pretend to support restart-safe
// source reconciliation.
type PermissionSnapshotReader interface {
	CurrentSourceSnapshot(context.Context, PermissionSourceSnapshotRequest) (PermissionSourceSnapshot, error)
}

func NewPermissionReconcileRequest(application ApplicationRef, sourceOwner, previousSnapshotHash string, definitions []PermissionDefinition) (PermissionReconcileRequest, error) {
	snapshotHash, err := PermissionSnapshotHash(sourceOwner, definitions)
	if err != nil {
		return PermissionReconcileRequest{}, err
	}
	request := PermissionReconcileRequest{
		Application: application, SourceOwner: strings.TrimSpace(sourceOwner),
		PreviousSnapshotHash: strings.TrimSpace(previousSnapshotHash), SnapshotHash: snapshotHash,
		Definitions: append([]PermissionDefinition(nil), definitions...),
	}
	if err := request.ValidateContract(); err != nil {
		return PermissionReconcileRequest{}, err
	}
	return request, nil
}

func (request PermissionReconcileRequest) ValidateContract() error {
	if !request.Application.WorkspaceID.Valid() || !request.Application.ApplicationKey.Valid() {
		return &Error{Code: "identity.permission_reconcile_scope_invalid"}
	}
	if !validSourceOwner(request.SourceOwner) {
		return &Error{Code: "identity.permission_source_owner_invalid"}
	}
	if previous := strings.TrimSpace(request.PreviousSnapshotHash); previous != "" && !validPermissionSnapshotHash(previous) {
		return &Error{Code: "identity.permission_previous_snapshot_hash_invalid"}
	}
	seen := make(map[string]struct{}, len(request.Definitions))
	for _, definition := range request.Definitions {
		key := strings.TrimSpace(definition.PermissionKey)
		resourceKey := strings.TrimSpace(definition.ResourceKey)
		actionKey := strings.TrimSpace(definition.ActionKey)
		if key == "" || resourceKey == "" || actionKey == "" || strings.TrimSpace(definition.Label) == "" || strings.TrimSpace(definition.Category) == "" || strings.TrimSpace(definition.SourceKind) == "" || key != resourceKey+"."+actionKey {
			return &Error{Code: "identity.permission_definition_invalid"}
		}
		if _, duplicate := seen[key]; duplicate {
			return &Error{Code: "identity.permission_definition_duplicate"}
		}
		seen[key] = struct{}{}
	}
	snapshotHash, err := PermissionSnapshotHash(request.SourceOwner, request.Definitions)
	if err != nil || strings.TrimSpace(request.SnapshotHash) != snapshotHash {
		return &Error{Code: "identity.permission_snapshot_hash_invalid"}
	}
	return nil
}

func validPermissionSnapshotHash(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

// PermissionSnapshotHash is the wire-contract hash for one source owner's
// complete PermissionDefinition set. It intentionally excludes database IDs,
// timestamps, lifecycle state, and the administrator-owned enabled switch.
func PermissionSnapshotHash(sourceOwner string, definitions []PermissionDefinition) (string, error) {
	sourceOwner = strings.TrimSpace(sourceOwner)
	if !validSourceOwner(sourceOwner) {
		return "", &Error{Code: "identity.permission_source_owner_invalid"}
	}
	type snapshotEntry struct {
		PermissionKey  string `json:"permission_key"`
		DefinitionHash string `json:"definition_hash"`
	}
	entries := make([]snapshotEntry, 0, len(definitions))
	seen := make(map[string]struct{}, len(definitions))
	for _, definition := range definitions {
		key := strings.TrimSpace(definition.PermissionKey)
		resourceKey := strings.TrimSpace(definition.ResourceKey)
		actionKey := strings.TrimSpace(definition.ActionKey)
		canonical := struct {
			PermissionKey string `json:"permission_key"`
			ResourceKey   string `json:"resource_key"`
			ActionKey     string `json:"action_key"`
			Label         string `json:"label"`
			Description   string `json:"description"`
			Category      string `json:"category"`
			SourceKind    string `json:"source_kind"`
			SourceOwner   string `json:"source_owner"`
		}{
			PermissionKey: key, ResourceKey: resourceKey, ActionKey: actionKey,
			Label: strings.TrimSpace(definition.Label), Description: strings.TrimSpace(definition.Description),
			Category: strings.TrimSpace(definition.Category), SourceKind: strings.TrimSpace(definition.SourceKind), SourceOwner: sourceOwner,
		}
		if canonical.PermissionKey == "" || canonical.ResourceKey == "" || canonical.ActionKey == "" || canonical.Label == "" || canonical.Category == "" || canonical.SourceKind == "" || canonical.PermissionKey != canonical.ResourceKey+"."+canonical.ActionKey {
			return "", &Error{Code: "identity.permission_definition_invalid"}
		}
		if _, duplicate := seen[key]; duplicate {
			return "", &Error{Code: "identity.permission_definition_duplicate"}
		}
		seen[key] = struct{}{}
		rawDefinition, err := json.Marshal(canonical)
		if err != nil {
			return "", err
		}
		definitionHash := sha256.Sum256(rawDefinition)
		entries = append(entries, snapshotEntry{PermissionKey: key, DefinitionHash: hex.EncodeToString(definitionHash[:])})
	}
	sort.Slice(entries, func(left, right int) bool { return entries[left].PermissionKey < entries[right].PermissionKey })
	rawSnapshot, err := json.Marshal(entries)
	if err != nil {
		return "", err
	}
	snapshotHash := sha256.Sum256(rawSnapshot)
	return hex.EncodeToString(snapshotHash[:]), nil
}

func validSourceOwner(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 256 {
		return false
	}
	for index, character := range value {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || index > 0 && strings.ContainsRune("._:-", character) {
			continue
		}
		return false
	}
	return true
}
