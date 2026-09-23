package identity

// OperationsPersistenceBinding lets the host enable shared Operations
// persistence after `_operations` and `_operation_controls` have been
// installed in the owner database. Receipt-backed commands and portability
// controls fail closed until this binding is active.
type OperationsPersistenceBinding interface {
	BindOperationsPersistence() error
}
