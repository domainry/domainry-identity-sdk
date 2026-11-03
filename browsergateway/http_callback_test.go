package browsergateway

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	identity "github.com/domainry/domainry-identity-sdk"
)

func TestGatewayAuthorizesRegisteredHTTPCallback(t *testing.T) {
	for _, callback := range []string{
		"http://116.6.111.254:18080/auth/callback",
		"http://192.168.98.11:8081/auth/callback",
		"http://knowledge.internal/auth/callback",
	} {
		t.Run(callback, func(t *testing.T) {
			var captured identity.BrowserAuthorizationRequest
			gateway, err := New(testBinding{auth: &testAuthentication{}, ssoRequest: &captured}, Config{
				ApplicationKey: "identity-admin", DefaultWorkspaceID: "workspace-primary",
			})
			if err != nil {
				t.Fatal(err)
			}
			query := url.Values{
				"client_id": {"domainry-runtime"}, "redirect_uri": {callback}, "state": {"state-1"},
				"code_challenge": {"abcdefghijklmnopqrstuvwxyzABCDEFGH012345678"}, "code_challenge_method": {"S256"},
			}
			request := httptest.NewRequest(http.MethodGet, "/auth/authorize?"+query.Encode(), nil)
			request.AddCookie(&http.Cookie{Name: DefaultRefreshCookieName, Value: "enterprise-refresh"})
			response := httptest.NewRecorder()
			gateway.AuthorizeBrowserApplication(response, request)
			if response.Code != http.StatusSeeOther {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			location, err := url.Parse(response.Header().Get("Location"))
			if err != nil || location.Query().Get("code") != "one-time-code" || location.Query().Get("state") != "state-1" || captured.ReturnURL != callback {
				t.Fatalf("location=%q request=%#v err=%v", response.Header().Get("Location"), captured, err)
			}
		})
	}
}

func TestGatewayRejectsMalformedAuthorizationCallback(t *testing.T) {
	for _, callback := range []string{
		"http://user:password@116.6.111.254:18080/auth/callback",
		"http://116.6.111.254:18080/auth/callback#fragment",
		"http:///auth/callback", "https:///auth/callback", "javascript:alert(1)", "/auth/callback",
	} {
		if validReturnURL(callback) {
			t.Errorf("accepted invalid callback %q", callback)
		}
	}
}
