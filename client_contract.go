package identitysdk

import "context"

type SessionClient interface {
	Login(context.Context, LoginRequest) (AuthSession, error)
	Refresh(context.Context, string) (AuthSession, error)
	Logout(context.Context, string) error
}

type ProviderClient interface {
	Providers(context.Context) ([]Provider, error)
	StartProvider(context.Context, string, ProviderStartRequest) (ProviderChallenge, error)
	VerifyProvider(context.Context, string, ProviderVerifyRequest) (AuthSession, error)
	CompleteProviderCallback(context.Context, string, ProviderCallback) (AuthSession, error)
}

// Client is the deployment-neutral Identity SDK contract. Both the remote
// SaaS client and the in-process module client implement this interface.
type Client interface {
	Authenticator
	Authorizer
	SessionClient
	ProviderClient
}
