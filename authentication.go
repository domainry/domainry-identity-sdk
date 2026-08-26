package identitysdk

type AuthSession struct {
	WorkspaceID        string   `json:"workspace_id"`
	AccessToken        string   `json:"access_token"`
	RefreshToken       string   `json:"refresh_token,omitempty"`
	TokenType          string   `json:"token_type"`
	ExpiresAt          string   `json:"expires_at"`
	User               User     `json:"user"`
	Roles              []Role   `json:"roles"`
	DefaultRole        string   `json:"default_role"`
	Permissions        []string `json:"permissions"`
	MustChangePassword bool     `json:"must_change_password"`
}

type LoginRequest struct {
	WorkspaceID string `json:"workspace_id"`
	Login       string `json:"login"`
	Password    string `json:"password"`
}

type Provider struct {
	Key            string   `json:"key"`
	Label          string   `json:"label"`
	Type           string   `json:"type"`
	Enabled        bool     `json:"enabled"`
	Priority       string   `json:"priority,omitempty"`
	Market         string   `json:"market,omitempty"`
	Markets        []string `json:"markets,omitempty"`
	Channels       []string `json:"channels,omitempty"`
	SelectedMarket string   `json:"selected_market,omitempty"`
	MarketFit      string   `json:"market_fit,omitempty"`
	Issuer         string   `json:"issuer,omitempty"`
	AuthURL        string   `json:"auth_url,omitempty"`
	RedirectURL    string   `json:"redirect_url,omitempty"`
	Scope          string   `json:"scope,omitempty"`
}

type ProviderStartRequest struct {
	WorkspaceID string `json:"workspace_id"`
	Phone       string `json:"phone,omitempty"`
}

type ProviderChallenge struct {
	Provider  string `json:"provider"`
	State     string `json:"state"`
	Nonce     string `json:"nonce,omitempty"`
	Code      string `json:"code,omitempty"`
	AuthURL   string `json:"auth_url,omitempty"`
	ExpiresAt string `json:"expires_at"`
}

type ProviderVerifyRequest struct {
	WorkspaceID string `json:"workspace_id"`
	State       string `json:"state"`
	Code        string `json:"code"`
}

type ProviderCallback struct {
	Values map[string]string
}
