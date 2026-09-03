package modulehost

import (
	"context"

	ormmigration "github.com/domainry/domainry-orm/migration"
)

// SchemaMigration is source-owned module DDL submitted to the embedding
// application's single migration registrar and ledger.
type SchemaMigration = ormmigration.Migration

// MigrationRegistrar lets nested Identity modules use the embedding host's
// database dialect, migration lock, and sole _schema_migrations ledger.
type MigrationRegistrar interface {
	Driver() string
	Schema() string
	ApplyOwnedMigrations(context.Context, string, []SchemaMigration) error
}
