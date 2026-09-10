package authentication

import "net/http"

// RequestCredentialBinding adapts external transport credentials. Cookie adapters
// enforce origin policy before accepting unsafe requests.
type RequestCredentialBinding interface {
	ReadAccessCredential(*http.Request) (string, error)
}
