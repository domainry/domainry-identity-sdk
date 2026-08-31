package identity

import (
	"fmt"
	"strings"
)

type TenantID string
type WorkspaceID string
type SubjectID string
type SessionID string
type ApplicationKey string
type ResourceType string
type Action string
type AuthorizationRevision string
type CatalogRevision string

func (value TenantID) Valid() bool              { return validTenantBoundaryIdentifier(string(value)) }
func (value WorkspaceID) Valid() bool           { return validTenantBoundaryIdentifier(string(value)) }
func (value SubjectID) Valid() bool             { return validIdentifier(string(value)) }
func (value SessionID) Valid() bool             { return validIdentifier(string(value)) }
func (value ApplicationKey) Valid() bool        { return validIdentifier(string(value)) }
func (value ResourceType) Valid() bool          { return validIdentifier(string(value)) }
func (value Action) Valid() bool                { return validIdentifier(string(value)) }
func (value AuthorizationRevision) Valid() bool { return validIdentifier(string(value)) }
func (value CatalogRevision) Valid() bool       { return validIdentifier(string(value)) }

func ValidateIdentifier(name, value string) error {
	if !validIdentifier(value) {
		return fmt.Errorf("%s must be a non-empty canonical identifier", name)
	}
	return nil
}

func validIdentifier(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 256 {
		return false
	}
	for _, character := range value {
		if character <= 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

// validTenantBoundaryIdentifier rejects the historical "default" fallback.
// A tenant boundary must name a workspace that was explicitly initialized;
// using a placeholder would silently collapse isolation.
func validTenantBoundaryIdentifier(value string) bool {
	return validIdentifier(value) && !strings.EqualFold(strings.TrimSpace(value), "default")
}
