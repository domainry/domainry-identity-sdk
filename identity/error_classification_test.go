package identity

import (
	"testing"

	"github.com/domainry/domainry-foundation/apperror"
)

func TestErrorClassificationContract(t *testing.T) {
	tests := []struct {
		status int
		kind   apperror.ErrorKind
		code   string
	}{
		{400, apperror.KindBadRequest, "identity.validation_failed"},
		{403, apperror.KindForbidden, "identity.permission_denied"},
		{404, apperror.KindNotFound, "identity.subject_not_found"},
		{409, apperror.KindConflict, "identity.write_fence_rejected"},
		{429, apperror.KindRateLimited, "identity.rate_limited"},
		{503, apperror.KindUnavailable, "identity.database_unavailable"},
	}
	for _, test := range tests {
		err := &Error{StatusCode: test.status, Code: test.code, Params: map[string]string{"field": "id"}}
		if got := apperror.KindOf(err); got != test.kind {
			t.Fatalf("status=%d kind=%q", test.status, got)
		}
		if got := apperror.CodeOf(err); got != test.code || apperror.ParamsOf(err)["field"] != "id" {
			t.Fatalf("status=%d code=%q params=%#v", test.status, got, apperror.ParamsOf(err))
		}
	}
}
