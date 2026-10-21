package identity

import (
	"testing"

	"github.com/domainry/domainry-foundation/apperror"
)

func TestErrorClassificationContract(t *testing.T) {
	tests := []struct {
		class ErrorClass
		kind  apperror.ErrorKind
		code  string
	}{
		{ErrorClassBadRequest, apperror.KindBadRequest, "identity.validation_failed"},
		{ErrorClassForbidden, apperror.KindForbidden, "identity.permission_denied"},
		{ErrorClassNotFound, apperror.KindNotFound, "identity.subject_not_found"},
		{ErrorClassConflict, apperror.KindConflict, "identity.write_fence_rejected"},
		{ErrorClassRateLimited, apperror.KindRateLimited, "identity.rate_limited"},
		{ErrorClassUnavailable, apperror.KindUnavailable, "identity.database_unavailable"},
	}
	for _, test := range tests {
		err := &Error{Class: test.class, Code: test.code, Params: map[string]string{"field": "id"}}
		if got := apperror.KindOf(err); got != test.kind {
			t.Fatalf("class=%q kind=%q", test.class, got)
		}
		if got := apperror.CodeOf(err); got != test.code || apperror.ParamsOf(err)["field"] != "id" {
			t.Fatalf("class=%q code=%q params=%#v", test.class, got, apperror.ParamsOf(err))
		}
	}
}
