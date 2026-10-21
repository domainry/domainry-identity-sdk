package identity

import (
	"fmt"
	"strings"

	"github.com/domainry/domainry-foundation/apperror"
)

type ErrorClass = apperror.ErrorKind

const (
	ErrorClassBadRequest  = apperror.KindBadRequest
	ErrorClassForbidden   = apperror.KindForbidden
	ErrorClassNotFound    = apperror.KindNotFound
	ErrorClassConflict    = apperror.KindConflict
	ErrorClassRateLimited = apperror.KindRateLimited
	ErrorClassUnavailable = apperror.KindUnavailable
	ErrorClassInternal    = apperror.KindInternal
)

type Error struct {
	Class     ErrorClass        `json:"-"`
	Code      string            `json:"code"`
	Message   string            `json:"message,omitempty"`
	RequestID string            `json:"request_id,omitempty"`
	Params    map[string]string `json:"params,omitempty"`
	Cause     error             `json:"-"`
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.Code != "" && e.Message != "" {
		return fmt.Sprintf("%s: %s", e.Code, e.Message)
	}
	if e.Code != "" {
		return e.Code
	}
	if e.Message != "" {
		return e.Message
	}
	if e.Cause != nil {
		return e.Cause.Error()
	}
	return "identity request failed"
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

func (e *Error) ApplicationErrorKind() string {
	if e == nil {
		return ""
	}
	return string(apperror.NormalizeKind(string(e.Class)))
}

func (e *Error) ErrorCode() string {
	if e == nil {
		return ""
	}
	return strings.TrimSpace(e.Code)
}

func (e *Error) ErrorParams() map[string]string {
	if e == nil || len(e.Params) == 0 {
		return nil
	}
	result := make(map[string]string, len(e.Params))
	for key, value := range e.Params {
		result[key] = value
	}
	return result
}
