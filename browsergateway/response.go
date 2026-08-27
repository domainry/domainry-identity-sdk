package browsergateway

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	identity "github.com/domainry/domainry-identity-sdk"
)

func (gateway *Gateway) writeError(w http.ResponseWriter, err error) {
	status, code, message, requestID := http.StatusInternalServerError, "identity.request_failed", "", ""
	params := map[string]string(nil)
	var sdkError *identity.Error
	if errors.As(err, &sdkError) {
		if sdkError.StatusCode >= 400 && sdkError.StatusCode <= 599 {
			status = sdkError.StatusCode
		}
		if strings.TrimSpace(sdkError.Code) != "" {
			code = sdkError.Code
		}
		message, requestID, params = sdkError.Message, sdkError.RequestID, sdkError.Params
	}
	payload := map[string]any{"code": code, "error": map[string]any{"code": code}}
	if message != "" {
		payload["message"] = message
	}
	if requestID != "" {
		payload["request_id"] = requestID
	}
	if len(params) > 0 {
		payload["params"] = params
		payload["error"].(map[string]any)["params"] = params
	}
	gateway.writeJSON(w, status, payload)
}

func (gateway *Gateway) writeCode(w http.ResponseWriter, status int, code string) {
	gateway.writeJSON(w, status, map[string]any{"code": code, "error": map[string]string{"code": code}})
}

func (gateway *Gateway) writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if value != nil {
		_ = json.NewEncoder(w).Encode(value)
	}
}
