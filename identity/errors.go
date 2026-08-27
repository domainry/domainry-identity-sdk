package identity

import "fmt"

type Error struct {
	StatusCode int               `json:"-"`
	Code       string            `json:"code"`
	Message    string            `json:"message,omitempty"`
	RequestID  string            `json:"request_id,omitempty"`
	Params     map[string]string `json:"params,omitempty"`
	Cause      error             `json:"-"`
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
