// Package modulehost defines the optional host capabilities required only by
// an in-process Identity module. Remote/SaaS factories depend on the root
// identity.Host contract and never import this package or database/sql.
package modulehost

import (
	"context"
	"database/sql"

	identity "github.com/domainry/domainry-identity-sdk"
)

// Host extends the deployment-neutral SDK host with persistence capabilities
// borrowed by an embedded Identity module.
type Host interface {
	identity.Host
	IdentityDatabase(context.Context) (Database, error)
	RegisterIdentityMigrations(context.Context, []Migration) error
}

// Database is host-owned. Identity may use the pool and namespace but must not
// close the pool or assume lifecycle ownership.
type Database struct {
	DB     *sql.DB
	Driver string
	Schema string
}

type Migration struct {
	Version string
	Up      func(context.Context, Database) error
}
