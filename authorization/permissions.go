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
	PermissionKey string                  `json:"permission_key"`
	ModuleKey     string                  `json:"module_key"`
	GroupKey      string                  `json:"group_key"`
	ResourceKey   string                  `json:"resource_key"`
	OperationKey  string                  `json:"operation_key"`
	Label         string                  `json:"label"`
	Description   string                  `json:"description,omitempty"`
	Category      string                  `json:"category"`
	SourceKind    string                  `json:"source_kind"`
	GrantMode     string                  `json:"grant_mode"`
	ScopeKind     string                  `json:"scope_kind"`
	ObjectKey     string                  `json:"object_key,omitempty"`
	DefaultLocale string                  `json:"default_locale"`
	I18n          PermissionLocalizedText `json:"i18n"`
}

type PermissionText struct {
	ModuleLabel    string `json:"module_label"`
	GroupLabel     string `json:"group_label"`
	ResourceLabel  string `json:"resource_label"`
	OperationLabel string `json:"operation_label"`
	Label          string `json:"label"`
	Description    string `json:"description,omitempty"`
}

type PermissionLocalizedText map[string]PermissionText

type PermissionReconcileRequest struct {
	SourceOwner          string                 `json:"source_owner"`
	PreviousSnapshotHash string                 `json:"previous_snapshot_hash,omitempty"`
	SnapshotHash         string                 `json:"snapshot_hash"`
	Definitions          []PermissionDefinition `json:"definitions"`
}

type PermissionReconcileReceipt struct {
	SourceOwner          string `json:"source_owner"`
	PreviousSnapshotHash string `json:"previous_snapshot_hash,omitempty"`
	SnapshotHash         string `json:"snapshot_hash"`
	DefinitionCount      int    `json:"definition_count"`
	Inserted             int    `json:"inserted"`
	Updated              int    `json:"updated"`
	Retired              int    `json:"retired"`
	Unchanged            int    `json:"unchanged"`
}

type PermissionSourceSnapshotRequest struct {
	SourceOwner string `json:"source_owner"`
}

func (request PermissionSourceSnapshotRequest) ValidateContract() error {
	if !validSourceOwner(request.SourceOwner) {
		return &Error{Class: ErrorClassBadRequest, Code: "identity.permission_source_owner_invalid"}
	}
	return nil
}

type PermissionSourceSnapshot struct {
	SourceOwner  string                 `json:"source_owner"`
	SnapshotHash string                 `json:"snapshot_hash,omitempty"`
	Definitions  []PermissionDefinition `json:"definitions,omitempty"`
}

func (snapshot PermissionSourceSnapshot) ValidateFor(request PermissionSourceSnapshotRequest) error {
	if err := request.ValidateContract(); err != nil {
		return err
	}
	hash := strings.TrimSpace(snapshot.SnapshotHash)
	if strings.TrimSpace(snapshot.SourceOwner) != strings.TrimSpace(request.SourceOwner) ||
		hash != "" && !validPermissionSnapshotHash(hash) || hash == "" && len(snapshot.Definitions) != 0 {
		return &Error{Class: ErrorClassBadRequest, Code: "identity.permission_source_snapshot_invalid"}
	}
	if hash != "" {
		computed, err := PermissionSnapshotHash(request.SourceOwner, snapshot.Definitions)
		if err != nil || computed != hash {
			return &Error{Class: ErrorClassBadRequest, Code: "identity.permission_source_snapshot_invalid"}
		}
	}
	return nil
}

// ValidateFor proves that a successful reconcile response acknowledges the
// exact global source owner and immutable definition snapshot submitted by the
// caller. Identity may report the submitted previous hash or the new snapshot
// hash when an idempotent retry observes that snapshot already applied.
func (receipt PermissionReconcileReceipt) ValidateFor(request PermissionReconcileRequest) error {
	if err := request.ValidateContract(); err != nil {
		return err
	}
	previousMatches := receipt.PreviousSnapshotHash == request.PreviousSnapshotHash || receipt.PreviousSnapshotHash == request.SnapshotHash
	if strings.TrimSpace(receipt.SourceOwner) != request.SourceOwner ||
		strings.TrimSpace(receipt.SnapshotHash) != request.SnapshotHash ||
		receipt.DefinitionCount != len(request.Definitions) || !previousMatches ||
		receipt.Inserted < 0 || receipt.Updated < 0 || receipt.Retired < 0 || receipt.Unchanged < 0 {
		return &Error{Class: ErrorClassBadRequest, Code: "identity.permission_reconcile_receipt_invalid"}
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

func NewPermissionReconcileRequest(sourceOwner, previousSnapshotHash string, definitions []PermissionDefinition) (PermissionReconcileRequest, error) {
	canonicalDefinitions, err := canonicalPermissionDefinitions(definitions)
	if err != nil {
		return PermissionReconcileRequest{}, err
	}
	snapshotHash, err := PermissionSnapshotHash(sourceOwner, canonicalDefinitions)
	if err != nil {
		return PermissionReconcileRequest{}, err
	}
	request := PermissionReconcileRequest{
		SourceOwner:          strings.TrimSpace(sourceOwner),
		PreviousSnapshotHash: strings.TrimSpace(previousSnapshotHash), SnapshotHash: snapshotHash,
		Definitions: canonicalDefinitions,
	}
	if err := request.ValidateContract(); err != nil {
		return PermissionReconcileRequest{}, err
	}
	return request, nil
}

func (request PermissionReconcileRequest) ValidateContract() error {
	if !validSourceOwner(request.SourceOwner) {
		return &Error{Class: ErrorClassBadRequest, Code: "identity.permission_source_owner_invalid"}
	}
	if previous := strings.TrimSpace(request.PreviousSnapshotHash); previous != "" && !validPermissionSnapshotHash(previous) {
		return &Error{Class: ErrorClassBadRequest, Code: "identity.permission_previous_snapshot_hash_invalid"}
	}
	seen := make(map[string]struct{}, len(request.Definitions))
	for _, definition := range request.Definitions {
		canonical, err := canonicalPermissionDefinition(definition)
		if err != nil {
			return &Error{Class: ErrorClassBadRequest, Code: "identity.permission_definition_invalid"}
		}
		key := canonical.PermissionKey
		if _, duplicate := seen[key]; duplicate {
			return &Error{Class: ErrorClassBadRequest, Code: "identity.permission_definition_duplicate"}
		}
		seen[key] = struct{}{}
	}
	snapshotHash, err := PermissionSnapshotHash(request.SourceOwner, request.Definitions)
	if err != nil || strings.TrimSpace(request.SnapshotHash) != snapshotHash {
		return &Error{Class: ErrorClassBadRequest, Code: "identity.permission_snapshot_hash_invalid"}
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
		return "", &Error{Class: ErrorClassBadRequest, Code: "identity.permission_source_owner_invalid"}
	}
	type snapshotEntry struct {
		PermissionKey  string `json:"permission_key"`
		DefinitionHash string `json:"definition_hash"`
	}
	entries := make([]snapshotEntry, 0, len(definitions))
	seen := make(map[string]struct{}, len(definitions))
	for _, definition := range definitions {
		canonical, err := canonicalPermissionDefinition(definition)
		if err != nil {
			return "", err
		}
		key := canonical.PermissionKey
		if _, duplicate := seen[key]; duplicate {
			return "", &Error{Class: ErrorClassBadRequest, Code: "identity.permission_definition_duplicate"}
		}
		seen[key] = struct{}{}
		rawDefinition, err := json.Marshal(struct {
			PermissionKey string                  `json:"permission_key"`
			ModuleKey     string                  `json:"module_key"`
			GroupKey      string                  `json:"group_key"`
			ResourceKey   string                  `json:"resource_key"`
			OperationKey  string                  `json:"operation_key"`
			Label         string                  `json:"label"`
			Description   string                  `json:"description"`
			Category      string                  `json:"category"`
			SourceKind    string                  `json:"source_kind"`
			GrantMode     string                  `json:"grant_mode"`
			ScopeKind     string                  `json:"scope_kind"`
			ObjectKey     string                  `json:"object_key"`
			DefaultLocale string                  `json:"default_locale"`
			I18n          PermissionLocalizedText `json:"i18n"`
			SourceOwner   string                  `json:"source_owner"`
		}{
			PermissionKey: canonical.PermissionKey, ModuleKey: canonical.ModuleKey, GroupKey: canonical.GroupKey,
			ResourceKey: canonical.ResourceKey, OperationKey: canonical.OperationKey, Label: canonical.Label,
			Description: canonical.Description, Category: canonical.Category, SourceKind: canonical.SourceKind,
			GrantMode: canonical.GrantMode, ScopeKind: canonical.ScopeKind, ObjectKey: canonical.ObjectKey,
			DefaultLocale: canonical.DefaultLocale, I18n: canonical.I18n, SourceOwner: sourceOwner,
		})
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

func canonicalPermissionDefinitions(source []PermissionDefinition) ([]PermissionDefinition, error) {
	result := make([]PermissionDefinition, len(source))
	for index, definition := range source {
		canonical, err := canonicalPermissionDefinition(definition)
		if err != nil {
			return nil, err
		}
		result[index] = canonical
	}
	return result, nil
}

func canonicalPermissionDefinition(source PermissionDefinition) (PermissionDefinition, error) {
	result := source
	result.PermissionKey = strings.TrimSpace(source.PermissionKey)
	result.ModuleKey = strings.TrimSpace(source.ModuleKey)
	result.GroupKey = strings.TrimSpace(source.GroupKey)
	result.ResourceKey = strings.TrimSpace(source.ResourceKey)
	result.OperationKey = strings.TrimSpace(source.OperationKey)
	result.Label = strings.TrimSpace(source.Label)
	result.Description = strings.TrimSpace(source.Description)
	result.Category = strings.TrimSpace(source.Category)
	result.SourceKind = strings.TrimSpace(source.SourceKind)
	result.GrantMode = strings.TrimSpace(source.GrantMode)
	result.ScopeKind = strings.TrimSpace(source.ScopeKind)
	result.ObjectKey = strings.TrimSpace(source.ObjectKey)
	result.DefaultLocale = strings.TrimSpace(source.DefaultLocale)
	result.I18n = make(PermissionLocalizedText, len(source.I18n))
	for rawLocale, rawText := range source.I18n {
		locale := strings.TrimSpace(rawLocale)
		if locale == "" {
			return PermissionDefinition{}, &Error{Class: ErrorClassBadRequest, Code: "identity.permission_definition_invalid"}
		}
		result.I18n[locale] = PermissionText{
			ModuleLabel: strings.TrimSpace(rawText.ModuleLabel), GroupLabel: strings.TrimSpace(rawText.GroupLabel),
			ResourceLabel: strings.TrimSpace(rawText.ResourceLabel), OperationLabel: strings.TrimSpace(rawText.OperationLabel),
			Label: strings.TrimSpace(rawText.Label), Description: strings.TrimSpace(rawText.Description),
		}
	}
	text, found := result.I18n[result.DefaultLocale]
	validGrantMode := result.GrantMode == "direct" || result.GrantMode == "bundled" || result.GrantMode == "internal"
	validScope := result.ScopeKind == "none" && result.ObjectKey == "" || result.ScopeKind == "record" && validSourceOwner(result.ObjectKey)
	if !validSourceOwner(result.PermissionKey) || !validSourceOwner(result.ModuleKey) || !validSourceOwner(result.GroupKey) ||
		!validSourceOwner(result.ResourceKey) || !validSourceOwner(result.OperationKey) || result.PermissionKey != result.ResourceKey+"."+result.OperationKey ||
		result.Label == "" || result.Category == "" || result.SourceKind == "" || !validGrantMode || !validScope || result.DefaultLocale == "" || !found ||
		text.ModuleLabel == "" || text.GroupLabel == "" || text.ResourceLabel == "" || text.OperationLabel == "" || text.Label == "" {
		return PermissionDefinition{}, &Error{Class: ErrorClassBadRequest, Code: "identity.permission_definition_invalid"}
	}
	return result, nil
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
