package remote

import (
	"net/http"
	"strings"
)

var protectedIdentityHeaders = map[string]struct{}{
	"Authorization":  {},
	"Content-Length": {},
	"Content-Type":   {},
	"Cookie":         {},
	"Host":           {},
	"User-Agent":     {},
	"X-Workspace-Id": {},
}

func copyIdentityHeaders(target, source http.Header) {
	for key, values := range source {
		canonical := http.CanonicalHeaderKey(strings.TrimSpace(key))
		if canonical == "" {
			continue
		}
		if _, protected := protectedIdentityHeaders[canonical]; protected {
			continue
		}
		for _, value := range values {
			if value = strings.TrimSpace(value); value != "" {
				target.Add(canonical, value)
			}
		}
	}
}
